package com.ellan.mcace.core.authority;

import com.sun.security.auth.module.NTSystem;
import com.sun.security.auth.module.UnixSystem;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Fail-closed path, ownership, access-control and bounded-I/O helpers for authority material.
 * Authority files may not cross, or be reached through, a symbolic link, junction or other
 * special filesystem object.
 */
public final class AuthorityFilePreflight {
    private static final LinkOption[] NO_FOLLOW = {LinkOption.NOFOLLOW_LINKS};
    private static final Set<PosixFilePermission> PRIVATE_DIRECTORY_PERMISSIONS = Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE);
    private static final Set<PosixFilePermission> PRIVATE_FILE_PERMISSIONS = Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE);
    private static final Set<AclEntryFlag> PRIVATE_DIRECTORY_ACL_FLAGS = Set.of(
            AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT);
    private static final Set<AclEntryPermission> FULL_CONTROL_PERMISSIONS =
            Set.copyOf(EnumSet.allOf(AclEntryPermission.class));
    private static final Set<AclEntryPermission> INTEGRITY_WRITE_PERMISSIONS = Set.copyOf(
            EnumSet.of(
                    AclEntryPermission.WRITE_DATA,
                    AclEntryPermission.APPEND_DATA,
                    AclEntryPermission.WRITE_NAMED_ATTRS,
                    AclEntryPermission.WRITE_ATTRIBUTES,
                    AclEntryPermission.DELETE,
                    AclEntryPermission.DELETE_CHILD,
                    AclEntryPermission.WRITE_ACL,
                    AclEntryPermission.WRITE_OWNER));
    private static final int WINDOWS_ACL_HELPER_TIMEOUT_SECONDS = 15;

    private static final String WINDOWS_ACL_PROTECTION_CHECK = String.join(";",
            "$ErrorActionPreference='Stop'",
            "$p=[Environment]::GetEnvironmentVariable('MCACE_AUTHORITY_ACL_PATH','Process')",
            "if([string]::IsNullOrWhiteSpace($p)){exit 31}",
            "$a=Get-Acl -LiteralPath $p",
            "if(-not $a.AreAccessRulesProtected){exit 32}",
            "if(@($a.Access|Where-Object{$_.IsInherited}).Count -ne 0){exit 33}",
            "exit 0");

    private static final String WINDOWS_ACL_HARDEN = String.join(";",
            "$ErrorActionPreference='Stop'",
            "$p=[Environment]::GetEnvironmentVariable('MCACE_AUTHORITY_ACL_PATH','Process')",
            "$d=[Environment]::GetEnvironmentVariable('MCACE_AUTHORITY_ACL_DIRECTORY','Process')",
            "if([string]::IsNullOrWhiteSpace($p)){exit 41}",
            "$current=[Security.Principal.WindowsIdentity]::GetCurrent().User",
            "$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')",
            "if($d -ceq 'true'){$acl=New-Object Security.AccessControl.DirectorySecurity}"
                    + "else{$acl=New-Object Security.AccessControl.FileSecurity}",
            "$acl.SetOwner($current)",
            "$acl.SetAccessRuleProtection($true,$false)",
            "if($d -ceq 'true'){"
                    + "$inheritance=[Security.AccessControl.InheritanceFlags]::ContainerInherit"
                    + " -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit;"
                    + "foreach($identity in @($current,$system)){"
                    + "$rule=New-Object Security.AccessControl.FileSystemAccessRule("
                    + "$identity,[Security.AccessControl.FileSystemRights]::FullControl,"
                    + "$inheritance,[Security.AccessControl.PropagationFlags]::None,"
                    + "[Security.AccessControl.AccessControlType]::Allow);"
                    + "[void]$acl.AddAccessRule($rule)}}else{"
                    + "foreach($identity in @($current,$system)){"
                    + "$rule=New-Object Security.AccessControl.FileSystemAccessRule("
                    + "$identity,[Security.AccessControl.FileSystemRights]::FullControl,"
                    + "[Security.AccessControl.AccessControlType]::Allow);"
                    + "[void]$acl.AddAccessRule($rule)}}",
            "Set-Acl -LiteralPath $p -AclObject $acl",
            "$after=Get-Acl -LiteralPath $p",
            "if(-not $after.AreAccessRulesProtected){exit 42}",
            "if(@($after.Access|Where-Object{$_.IsInherited}).Count -ne 0){exit 43}",
            "exit 0");

    private AuthorityFilePreflight() {
    }

    /** Creates a directory tree only after the existing prefix has passed no-follow checks. */
    public static Path createDirectoriesWithoutLinks(Path directory) throws IOException {
        Path normalized = absolute(directory);
        Path existing = nearestExistingAncestor(normalized);
        requireDirectoryChain(existing, "authority directory");
        try {
            Files.createDirectories(normalized);
        } catch (FileAlreadyExistsException exception) {
            throw new IOException("authority directory path is not a directory", exception);
        }
        requireDirectoryChain(normalized, "authority directory");
        return normalized;
    }

    /**
     * Creates every missing directory with an owner-only security descriptor and validates an
     * already-existing destination instead of silently repairing it.
     */
    public static Path createPrivateDirectoriesWithoutLinks(Path directory, String description)
            throws IOException {
        Path normalized = absolute(directory);
        Path existing = nearestExistingAncestor(normalized);
        requireDirectoryChain(existing, description);
        if (existing.equals(normalized)) {
            requirePrivateDirectory(normalized, description);
            return normalized;
        }

        List<Path> missing = new ArrayList<>();
        for (Path cursor = normalized; !cursor.equals(existing); cursor = cursor.getParent()) {
            if (cursor == null) {
                throw new IOException(description + " has no existing filesystem root");
            }
            missing.add(cursor);
        }
        for (int index = missing.size() - 1; index >= 0; index--) {
            Path candidate = missing.get(index);
            boolean created = false;
            try {
                createPrivateDirectoryNode(candidate, description);
                created = true;
            } catch (FileAlreadyExistsException ignored) {
                // A concurrent creator must still have produced the exact private directory.
            } catch (IOException exception) {
                if (created) {
                    deleteEmptyDirectoryQuietly(candidate);
                }
                throw exception;
            }
            try {
                requirePrivateDirectory(candidate, description);
            } catch (IOException exception) {
                if (created) {
                    deleteEmptyDirectoryQuietly(candidate);
                }
                throw exception;
            }
        }
        requirePrivateDirectory(normalized, description);
        return normalized;
    }

    /** Resolves a non-empty relative path without permitting lexical escape from {@code root}. */
    public static Path resolveRelative(Path root, String configured, String description)
            throws IOException {
        Path normalizedRoot = absolute(root);
        final Path relative;
        try {
            relative = Path.of(Objects.requireNonNull(configured, "configured"));
        } catch (RuntimeException exception) {
            throw new IOException(description + " is not a valid path", exception);
        }
        if (relative.isAbsolute() || relative.getNameCount() == 0
                || relative.toString().isBlank()) {
            throw new IOException(description + " must be relative to the authority data directory");
        }
        Path resolved = normalizedRoot.resolve(relative).normalize();
        if (!resolved.startsWith(normalizedRoot) || resolved.equals(normalizedRoot)) {
            throw new IOException(description + " escapes the authority data directory");
        }
        return resolved;
    }

    /** Verifies an existing regular file and all of its ancestors without following links. */
    public static void requireRegularFile(Path root, Path file, String description)
            throws IOException {
        CheckedPath checked = preflight(root, file, description);
        CheckedPath after = preflight(root, file, description);
        if (!checked.sameIdentity(after)) {
            throw new IOException(description + " changed during authority file preflight");
        }
    }

    /** Verifies one existing directory's identity, owner and exact private mode/DACL. */
    public static void requirePrivateDirectory(Path directory, String description)
            throws IOException {
        Path normalized = absolute(directory);
        CheckedDirectory before = preflightDirectory(normalized, description);
        SecurityContext security = securityContext(normalized, description);
        requirePrivateNode(normalized, true, description, security);
        CheckedDirectory after = preflightDirectory(normalized, description);
        requirePrivateNode(normalized, true, description, security);
        if (!before.sameIdentity(after)) {
            throw new IOException(description + " changed during private directory preflight");
        }
    }

    /**
     * Verifies that the root-to-leaf authority path is owned by the effective runtime principal
     * and has an exact owner/SYSTEM protected DACL on Windows or 0700/0600 on POSIX.
     */
    public static void requirePrivateRegularFile(Path root, Path file, String description)
            throws IOException {
        Path normalizedRoot = absolute(root);
        Path normalizedFile = absolute(file);
        CheckedPath before = preflight(normalizedRoot, normalizedFile, description);
        SecurityContext security = securityContext(normalizedRoot, description);
        requirePrivateDirectoryTree(
                normalizedRoot, normalizedFile.getParent(), description, security);
        requirePrivateNode(normalizedFile, false, description, security);
        CheckedPath after = preflight(normalizedRoot, normalizedFile, description);
        requirePrivateDirectoryTree(
                normalizedRoot, normalizedFile.getParent(), description, security);
        requirePrivateNode(normalizedFile, false, description, security);
        if (!before.sameIdentity(after)) {
            throw new IOException(description + " changed during private authority file preflight");
        }
    }

    /**
     * Verifies an integrity-sensitive public file. The root-to-leaf path must be owned by a
     * trusted runtime principal and must not grant write access to any other principal. Read and
     * traversal access may remain broader, so a normal POSIX 0755 directory plus 0644 public pin
     * is accepted while group-writable or world-writable material is rejected.
     */
    public static void requireIntegrityProtectedRegularFile(
            Path root, Path file, String description) throws IOException {
        Path normalizedRoot = absolute(root);
        Path normalizedFile = absolute(file);
        CheckedPath before = preflight(normalizedRoot, normalizedFile, description);
        SecurityContext security = securityContext(normalizedRoot, description);
        requireIntegrityProtectedDirectoryTree(
                normalizedRoot, normalizedFile.getParent(), description, security);
        requireIntegrityProtectedNode(normalizedFile, false, description, security);
        CheckedPath after = preflight(normalizedRoot, normalizedFile, description);
        requireIntegrityProtectedDirectoryTree(
                normalizedRoot, normalizedFile.getParent(), description, security);
        requireIntegrityProtectedNode(normalizedFile, false, description, security);
        if (!before.sameIdentity(after)) {
            throw new IOException(description + " changed during integrity preflight");
        }
    }

    /**
     * Verifies a private leaf under an integrity-protected (but not necessarily private) directory
     * tree. This is suitable for a 0600 credential below an owner-controlled 0755 application
     * directory without weakening the leaf credential's ACL.
     */
    public static void requirePrivateLeafRegularFile(
            Path root, Path file, String description) throws IOException {
        Path normalizedRoot = absolute(root);
        Path normalizedFile = absolute(file);
        CheckedPath before = preflight(normalizedRoot, normalizedFile, description);
        SecurityContext security = securityContext(normalizedRoot, description);
        requireIntegrityProtectedDirectoryTree(
                normalizedRoot, normalizedFile.getParent(), description, security);
        requirePrivateNode(normalizedFile, false, description, security);
        CheckedPath after = preflight(normalizedRoot, normalizedFile, description);
        requireIntegrityProtectedDirectoryTree(
                normalizedRoot, normalizedFile.getParent(), description, security);
        requirePrivateNode(normalizedFile, false, description, security);
        if (!before.sameIdentity(after)) {
            throw new IOException(description + " changed during private-leaf preflight");
        }
    }

    /**
     * Writes one owner-only file through a same-directory temporary, forced write and atomic move.
     * Existing destinations are rejected and never replaced.
     */
    public static void writePrivateFileAtomically(
            Path root, Path file, byte[] content, String description) throws IOException {
        publishPrivateFileAtomically(root, file, content, description, false);
    }

    /**
     * Replaces or creates one owner-only file through a forced same-directory temporary and an
     * atomic move. An existing destination must itself already pass the private-file contract.
     */
    public static void replacePrivateFileAtomically(
            Path root, Path file, byte[] content, String description) throws IOException {
        publishPrivateFileAtomically(root, file, content, description, true);
    }

    private static void publishPrivateFileAtomically(
            Path root,
            Path file,
            byte[] content,
            String description,
            boolean replaceExisting) throws IOException {
        byte[] safeContent = Objects.requireNonNull(content, "content").clone();
        Path temporary = null;
        try {
            Path normalizedRoot = absolute(root);
            Path normalizedFile = absolute(file);
            if (!normalizedFile.startsWith(normalizedRoot)
                    || normalizedFile.equals(normalizedRoot)) {
                throw new IOException(description + " is outside the authority data directory");
            }
            Path parent = Objects.requireNonNull(normalizedFile.getParent(), "file parent");
            SecurityContext security = securityContext(normalizedRoot, description);
            requirePrivateDirectoryTree(normalizedRoot, parent, description, security);
            boolean destinationExists = Files.exists(normalizedFile, NO_FOLLOW);
            if (destinationExists) {
                if (!replaceExisting) {
                    throw new FileAlreadyExistsException(normalizedFile.toString());
                }
                requirePrivateRegularFile(normalizedRoot, normalizedFile, description);
            }

            temporary = parent.resolve("." + normalizedFile.getFileName() + "."
                    + UUID.randomUUID().toString().replace("-", "") + ".tmp");
            boolean published = false;
            try {
                createPrivateFileNode(temporary, description, security);
                requirePrivateNode(temporary, false, description + " temporary", security);
                Set<OpenOption> options =
                        Set.of(StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                try (FileChannel channel = FileChannel.open(temporary, options)) {
                    ByteBuffer source = ByteBuffer.wrap(safeContent);
                    int zeroWrites = 0;
                    while (source.hasRemaining()) {
                        int count = channel.write(source);
                        if (count == 0 && ++zeroWrites > 8) {
                            throw new IOException(
                                    description + " made no progress during atomic write");
                        }
                        if (count > 0) {
                            zeroWrites = 0;
                        }
                    }
                    channel.force(true);
                }
                requirePrivateNode(temporary, false, description + " temporary", security);
                try {
                    if (replaceExisting) {
                        Files.move(temporary, normalizedFile,
                                StandardCopyOption.ATOMIC_MOVE,
                                StandardCopyOption.REPLACE_EXISTING);
                    } else {
                        Files.move(temporary, normalizedFile, StandardCopyOption.ATOMIC_MOVE);
                    }
                } catch (AtomicMoveNotSupportedException exception) {
                    throw new IOException(
                            description + " filesystem does not support atomic publish", exception);
                }
                published = true;
                requirePrivateRegularFile(normalizedRoot, normalizedFile, description);
            } catch (IOException exception) {
                if (published && !replaceExisting) {
                    Files.deleteIfExists(normalizedFile);
                }
                throw exception;
            }
        } finally {
            try {
                if (temporary != null) {
                    Files.deleteIfExists(temporary);
                }
            } finally {
                java.util.Arrays.fill(safeContent, (byte) 0);
            }
        }
    }

    /**
     * Reads an existing regular file after checking its declared size, and refuses growth,
     * replacement or path-identity changes observed during the read.
     */
    public static byte[] readBoundedRegularFile(
            Path root, Path file, int maximumBytes, String description) throws IOException {
        if (maximumBytes <= 0) {
            throw new IllegalArgumentException("maximumBytes must be positive");
        }
        CheckedPath before = preflight(root, file, description);
        long declaredSize = before.attributes().size();
        if (declaredSize > maximumBytes) {
            throw new IOException(description + " exceeds " + maximumBytes + " bytes");
        }

        byte[] content = null;
        boolean completed = false;
        try {
            OpenOption[] options = {StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS};
            try (FileChannel channel = FileChannel.open(before.file(), options)) {
                long openedSize = channel.size();
                if (openedSize < 0L || openedSize > maximumBytes) {
                    throw new IOException(description + " exceeds " + maximumBytes + " bytes");
                }
                content = new byte[(int) openedSize];
                ByteBuffer destination = ByteBuffer.wrap(content);
                int zeroReads = 0;
                while (destination.hasRemaining()) {
                    int count = channel.read(destination);
                    if (count < 0) {
                        byte[] original = content;
                        byte[] shortened = new byte[destination.position()];
                        System.arraycopy(original, 0, shortened, 0, shortened.length);
                        java.util.Arrays.fill(original, (byte) 0);
                        content = shortened;
                        break;
                    }
                    if (count == 0 && ++zeroReads > 8) {
                        throw new IOException(description + " made no progress during bounded read");
                    }
                    if (count > 0) {
                        zeroReads = 0;
                    }
                }
                ByteBuffer overflowProbe = ByteBuffer.allocate(1);
                if (channel.read(overflowProbe) >= 0 || channel.size() > maximumBytes) {
                    throw new IOException(description + " grew during bounded read");
                }
            }

            CheckedPath after = preflight(root, file, description);
            if (!before.sameIdentity(after)) {
                throw new IOException(description + " changed during bounded read");
            }
            completed = true;
            return content;
        } finally {
            if (!completed && content != null) {
                java.util.Arrays.fill(content, (byte) 0);
            }
        }
    }

    /** Bounded read plus private owner/mode/DACL validation before and after the read. */
    public static byte[] readBoundedPrivateRegularFile(
            Path root, Path file, int maximumBytes, String description) throws IOException {
        requirePrivateRegularFile(root, file, description);
        byte[] result = readBoundedRegularFile(root, file, maximumBytes, description);
        try {
            requirePrivateRegularFile(root, file, description);
            return result;
        } catch (IOException | RuntimeException exception) {
            java.util.Arrays.fill(result, (byte) 0);
            throw exception;
        }
    }

    /** Bounded read plus integrity-only owner/write validation before and after the read. */
    public static byte[] readBoundedIntegrityProtectedRegularFile(
            Path root, Path file, int maximumBytes, String description) throws IOException {
        requireIntegrityProtectedRegularFile(root, file, description);
        byte[] result = readBoundedRegularFile(root, file, maximumBytes, description);
        requireIntegrityProtectedRegularFile(root, file, description);
        return result;
    }

    /** Bounded read of a private leaf below an integrity-protected directory tree. */
    public static byte[] readBoundedPrivateLeafRegularFile(
            Path root, Path file, int maximumBytes, String description) throws IOException {
        requirePrivateLeafRegularFile(root, file, description);
        byte[] result = readBoundedRegularFile(root, file, maximumBytes, description);
        try {
            requirePrivateLeafRegularFile(root, file, description);
            return result;
        } catch (IOException | RuntimeException exception) {
            java.util.Arrays.fill(result, (byte) 0);
            throw exception;
        }
    }

    private static void createPrivateDirectoryNode(Path directory, String description)
            throws IOException {
        Path parent = Objects.requireNonNull(directory.getParent(), "directory parent");
        SecurityContext parentSecurity = securityContext(parent, description);
        if (parentSecurity.platform() == SecurityPlatform.POSIX) {
            FileAttribute<Set<PosixFilePermission>> attribute =
                    PosixFilePermissions.asFileAttribute(PRIVATE_DIRECTORY_PERMISSIONS);
            Files.createDirectory(directory, attribute);
        } else {
            Files.createDirectory(directory);
            try {
                runWindowsAclHelper(directory, true, WINDOWS_ACL_HARDEN, description);
            } catch (IOException exception) {
                deleteEmptyDirectoryQuietly(directory);
                throw exception;
            }
        }
    }

    private static void createPrivateFileNode(
            Path file, String description, SecurityContext security) throws IOException {
        if (security.platform() == SecurityPlatform.POSIX) {
            FileAttribute<Set<PosixFilePermission>> attribute =
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE_PERMISSIONS);
            Files.createFile(file, attribute);
        } else {
            Files.createFile(file);
            try {
                runWindowsAclHelper(file, false, WINDOWS_ACL_HARDEN, description);
            } catch (IOException exception) {
                Files.deleteIfExists(file);
                throw exception;
            }
        }
    }

    private static void requirePrivateDirectoryTree(
            Path root, Path directory, String description, SecurityContext security)
            throws IOException {
        Path normalizedRoot = absolute(root);
        Path normalizedDirectory = absolute(directory);
        if (!normalizedDirectory.startsWith(normalizedRoot)) {
            throw new IOException(description + " private directory escapes authority root");
        }
        Path current = normalizedRoot;
        requirePrivateNode(current, true, description + " root", security);
        Path relative = normalizedRoot.relativize(normalizedDirectory);
        for (Path component : relative) {
            current = current.resolve(component);
            requirePrivateNode(current, true, description + " directory", security);
        }
    }

    private static void requireIntegrityProtectedDirectoryTree(
            Path root, Path directory, String description, SecurityContext security)
            throws IOException {
        Path normalizedRoot = absolute(root);
        Path normalizedDirectory = absolute(directory);
        if (!normalizedDirectory.startsWith(normalizedRoot)) {
            throw new IOException(description + " integrity directory escapes authority root");
        }
        Path current = normalizedRoot;
        requireIntegrityProtectedNode(current, true, description + " root", security);
        Path relative = normalizedRoot.relativize(normalizedDirectory);
        for (Path component : relative) {
            current = current.resolve(component);
            requireIntegrityProtectedNode(
                    current, true, description + " directory", security);
        }
    }

    private static void requireIntegrityProtectedNode(
            Path path, boolean directory, String description, SecurityContext security)
            throws IOException {
        BasicFileAttributes basic = readNoFollow(path, description);
        if ((directory && !basic.isDirectory()) || (!directory && !basic.isRegularFile())
                || basic.isSymbolicLink() || basic.isOther()) {
            throw new IOException(description + " has the wrong no-follow filesystem type");
        }
        if (security.platform() == SecurityPlatform.POSIX) {
            requireIntegrityProtectedPosixNode(
                    path, description, security.effectiveUid());
        } else {
            requireIntegrityProtectedWindowsNode(path, description, security);
        }
    }

    private static void requireIntegrityProtectedPosixNode(
            Path path, String description, long effectiveUid)
            throws IOException {
        final PosixFileAttributes attributes;
        try {
            attributes = Files.readAttributes(
                    path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException exception) {
            throw new IOException(description + " cannot enforce POSIX owner/mode", exception);
        }
        final Object rawUid;
        try {
            rawUid = Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException exception) {
            throw new IOException(description + " cannot read the numeric POSIX owner", exception);
        }
        if (!(rawUid instanceof Number owner) || owner.longValue() != effectiveUid) {
            throw new IOException(description + " is not owned by the effective runtime UID");
        }
        Set<PosixFilePermission> permissions = attributes.permissions();
        boolean writableByAnotherPrincipal = permissions.contains(PosixFilePermission.GROUP_WRITE)
                || permissions.contains(PosixFilePermission.OTHERS_WRITE);
        if (writableByAnotherPrincipal) {
            throw new IOException(description + " grants write access outside the runtime owner");
        }
    }

    private static void requireIntegrityProtectedWindowsNode(
            Path path, String description, SecurityContext security) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException(description + " cannot enforce the Windows DACL");
        }
        UserPrincipal owner = view.getOwner();
        if (!isTrustedIntegrityPrincipal(owner, security)) {
            throw new IOException(description + " is not owned by a trusted Windows principal");
        }
        for (AclEntry entry : view.getAcl()) {
            if (entry.type() == AclEntryType.ALLOW
                    && !java.util.Collections.disjoint(
                            entry.permissions(), INTEGRITY_WRITE_PERMISSIONS)
                    && !isTrustedIntegrityPrincipal(entry.principal(), security)) {
                throw new IOException(description
                        + " grants Windows write access to an untrusted principal");
            }
        }
    }

    private static boolean isTrustedIntegrityPrincipal(
            UserPrincipal principal, SecurityContext security) {
        return samePrincipal(principal, security.effectivePrincipal())
                || samePrincipal(principal, security.systemPrincipal())
                || samePrincipal(principal, security.administratorsPrincipal());
    }

    private static void requirePrivateNode(
            Path path, boolean directory, String description, SecurityContext security)
            throws IOException {
        BasicFileAttributes basic = readNoFollow(path, description);
        if ((directory && !basic.isDirectory()) || (!directory && !basic.isRegularFile())
                || basic.isSymbolicLink() || basic.isOther()) {
            throw new IOException(description + " has the wrong no-follow filesystem type");
        }
        if (security.platform() == SecurityPlatform.POSIX) {
            requirePrivatePosixNode(path, directory, description, security.effectiveUid());
        } else {
            requirePrivateWindowsNode(path, directory, description, security);
        }
    }

    private static void requirePrivatePosixNode(
            Path path, boolean directory, String description, long effectiveUid)
            throws IOException {
        final PosixFileAttributes attributes;
        try {
            attributes = Files.readAttributes(
                    path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException exception) {
            throw new IOException(description + " cannot enforce POSIX owner/mode", exception);
        }
        final Object rawUid;
        try {
            rawUid = Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException exception) {
            throw new IOException(description + " cannot read the numeric POSIX owner", exception);
        }
        if (!(rawUid instanceof Number owner) || owner.longValue() != effectiveUid) {
            throw new IOException(description + " is not owned by the effective runtime UID");
        }
        Set<PosixFilePermission> expected = directory
                ? PRIVATE_DIRECTORY_PERMISSIONS : PRIVATE_FILE_PERMISSIONS;
        if (!attributes.permissions().equals(expected)) {
            throw new IOException(description + (directory
                    ? " directory mode must be 0700" : " file mode must be 0600"));
        }
    }

    private static void requirePrivateWindowsNode(
            Path path, boolean directory, String description, SecurityContext security)
            throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(
                path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException(description + " cannot enforce the Windows DACL");
        }
        UserPrincipal owner = view.getOwner();
        if (!samePrincipal(owner, security.effectivePrincipal())) {
            throw new IOException(description + " is not owned by the effective Windows principal");
        }
        List<AclEntry> acl = view.getAcl();
        if (acl.size() != 2) {
            throw new IOException(description + " Windows DACL must contain exactly two ACEs");
        }
        boolean currentSeen = false;
        boolean systemSeen = false;
        Set<AclEntryFlag> expectedFlags = directory ? PRIVATE_DIRECTORY_ACL_FLAGS : Set.of();
        for (AclEntry entry : acl) {
            if (entry.type() != AclEntryType.ALLOW
                    || !entry.flags().equals(expectedFlags)
                    || !entry.permissions().equals(FULL_CONTROL_PERMISSIONS)) {
                throw new IOException(description + " Windows DACL is not exact private FullControl");
            }
            if (samePrincipal(entry.principal(), security.effectivePrincipal())) {
                if (currentSeen) {
                    throw new IOException(description + " has a duplicate runtime-principal ACE");
                }
                currentSeen = true;
            } else if (samePrincipal(entry.principal(), security.systemPrincipal())) {
                if (systemSeen) {
                    throw new IOException(description + " has a duplicate SYSTEM ACE");
                }
                systemSeen = true;
            } else {
                throw new IOException(description + " Windows DACL grants an unexpected principal");
            }
        }
        if (!currentSeen || !systemSeen) {
            throw new IOException(description + " Windows DACL omits runtime principal or SYSTEM");
        }
        runWindowsAclHelper(path, directory, WINDOWS_ACL_PROTECTION_CHECK, description);
    }

    private static SecurityContext securityContext(Path path, String description)
            throws IOException {
        final boolean posix;
        final boolean acl;
        try {
            posix = Files.getFileStore(path).supportsFileAttributeView("posix");
            acl = Files.getFileStore(path).supportsFileAttributeView("acl");
        } catch (IOException exception) {
            throw new IOException(description + " cannot inspect filesystem security support",
                    exception);
        }
        if (posix) {
            try {
                long uid = new UnixSystem().getUid();
                if (uid < 0L) {
                    throw new IOException(description + " returned an invalid effective UID");
                }
                return new SecurityContext(SecurityPlatform.POSIX, uid, null, null, null);
            } catch (LinkageError | RuntimeException exception) {
                throw new IOException(description + " cannot resolve the effective POSIX UID",
                        exception);
            }
        }
        if (File.separatorChar == '\\' && acl) {
            try {
                NTSystem identity = new NTSystem();
                String name = identity.getName();
                String domain = identity.getDomain();
                if (name == null || name.isBlank()) {
                    throw new IOException(description + " returned an empty Windows principal");
                }
                String qualified = domain == null || domain.isBlank()
                        ? name : domain + "\\" + name;
                UserPrincipalLookupService lookup =
                        path.getFileSystem().getUserPrincipalLookupService();
                UserPrincipal current = lookup.lookupPrincipalByName(qualified);
                UserPrincipal system = lookup.lookupPrincipalByName("NT AUTHORITY\\SYSTEM");
                UserPrincipal administrators = lookup.lookupPrincipalByName(
                        "BUILTIN\\Administrators");
                return new SecurityContext(
                        SecurityPlatform.WINDOWS, -1L, current, system, administrators);
            } catch (LinkageError | RuntimeException exception) {
                throw new IOException(description + " cannot resolve the effective Windows principal",
                        exception);
            }
        }
        throw new IOException(description + " filesystem lacks a supported private ACL/mode view");
    }

    private static void runWindowsAclHelper(
            Path path, boolean directory, String script, String description) throws IOException {
        Path powerShell = windowsPowerShell(description);
        String encoded = Base64.getEncoder().encodeToString(
                script.getBytes(StandardCharsets.UTF_16LE));
        ProcessBuilder builder = new ProcessBuilder(
                powerShell.toString(), "-NoLogo", "-NoProfile", "-NonInteractive",
                "-WindowStyle", "Hidden", "-EncodedCommand", encoded);
        builder.environment().put("MCACE_AUTHORITY_ACL_PATH", absolute(path).toString());
        builder.environment().put("MCACE_AUTHORITY_ACL_DIRECTORY",
                Boolean.toString(directory));
        // A Java process launched from PowerShell 7 may inherit a PSModulePath that makes
        // Windows PowerShell 5.1 unable to autoload Microsoft.PowerShell.Security.
        builder.environment().remove("PSModulePath");
        builder.redirectErrorStream(true);
        final Process process;
        try {
            process = builder.start();
        } catch (IOException exception) {
            throw new IOException(description + " cannot start the Windows ACL verifier", exception);
        }
        boolean finished;
        try {
            finished = process.waitFor(WINDOWS_ACL_HELPER_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IOException(description + " Windows ACL verifier was interrupted", exception);
        }
        if (!finished) {
            process.destroyForcibly();
            throw new IOException(description + " Windows ACL verifier timed out");
        }
        if (process.exitValue() != 0) {
            byte[] raw = process.getInputStream().readNBytes(8192);
            String diagnostic = new String(raw, StandardCharsets.UTF_8).strip();
            throw new IOException(description
                    + " Windows DACL is inherited, unprotected or unverifiable"
                    + (diagnostic.isEmpty() ? "" : ": " + diagnostic));
        }
    }

    private static Path windowsPowerShell(String description) throws IOException {
        String systemRoot = System.getenv("SystemRoot");
        if (systemRoot == null || systemRoot.isBlank()) {
            throw new IOException(description + " cannot locate Windows PowerShell");
        }
        Path executable = Path.of(systemRoot, "System32", "WindowsPowerShell", "v1.0",
                "powershell.exe").toAbsolutePath().normalize();
        BasicFileAttributes attributes = readNoFollow(executable, description + " ACL verifier");
        if (!attributes.isRegularFile() || attributes.isSymbolicLink() || attributes.isOther()) {
            throw new IOException(description + " Windows PowerShell is not a no-follow regular file");
        }
        return executable;
    }

    private static CheckedPath preflight(Path root, Path file, String description)
            throws IOException {
        Path normalizedRoot = absolute(root);
        Path normalizedFile = absolute(file);
        if (!normalizedFile.startsWith(normalizedRoot) || normalizedFile.equals(normalizedRoot)) {
            throw new IOException(description + " is outside the authority data directory");
        }

        requireDirectoryChain(normalizedRoot, description + " root");
        Path parent = normalizedFile.getParent();
        if (parent == null) {
            throw new IOException(description + " has no parent directory");
        }
        requireDirectoryChain(parent, description + " parent");
        BasicFileAttributes attributes = readNoFollow(normalizedFile, description);
        if (!attributes.isRegularFile() || attributes.isSymbolicLink() || attributes.isOther()) {
            throw new IOException(description + " is not a no-follow regular file");
        }

        Path canonicalRoot = normalizedRoot.toRealPath(LinkOption.NOFOLLOW_LINKS);
        Path canonicalFile = normalizedFile.toRealPath(LinkOption.NOFOLLOW_LINKS);
        if (!canonicalFile.startsWith(canonicalRoot) || canonicalFile.equals(canonicalRoot)) {
            throw new IOException(description + " canonical path escapes the authority data directory");
        }
        return new CheckedPath(normalizedFile, canonicalRoot, canonicalFile, attributes);
    }

    private static CheckedDirectory preflightDirectory(Path directory, String description)
            throws IOException {
        requireDirectoryChain(directory, description);
        BasicFileAttributes attributes = readNoFollow(directory, description);
        Path canonical = directory.toRealPath(LinkOption.NOFOLLOW_LINKS);
        return new CheckedDirectory(directory, canonical, attributes);
    }

    private static void requireDirectoryChain(Path directory, String description)
            throws IOException {
        Path normalized = absolute(directory);
        List<Path> chain = new ArrayList<>();
        for (Path cursor = normalized; cursor != null; cursor = cursor.getParent()) {
            chain.add(cursor);
        }
        for (int index = chain.size() - 1; index >= 0; index--) {
            Path component = chain.get(index);
            BasicFileAttributes attributes = readNoFollow(component, description);
            if (!attributes.isDirectory() || attributes.isSymbolicLink() || attributes.isOther()) {
                throw new IOException(description + " crosses a link or non-directory component: "
                        + component);
            }
        }
    }

    private static Path nearestExistingAncestor(Path path) throws IOException {
        Path existing = path;
        while (existing != null && !Files.exists(existing, NO_FOLLOW)) {
            existing = existing.getParent();
        }
        if (existing == null) {
            throw new IOException("authority directory has no existing filesystem root");
        }
        return existing;
    }

    private static BasicFileAttributes readNoFollow(Path path, String description)
            throws IOException {
        try {
            return Files.readAttributes(path, BasicFileAttributes.class, NO_FOLLOW);
        } catch (IOException exception) {
            throw new IOException(description + " is missing or cannot be inspected: " + path,
                    exception);
        }
    }

    private static boolean samePrincipal(UserPrincipal first, UserPrincipal second) {
        return first != null && second != null
                && (first.equals(second)
                        || first.getName().equalsIgnoreCase(second.getName()));
    }

    private static void deleteEmptyDirectoryQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // The original hardening failure remains the actionable error.
        }
    }

    private static Path absolute(Path path) {
        return Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
    }

    private enum SecurityPlatform {
        POSIX,
        WINDOWS
    }

    private record SecurityContext(
            SecurityPlatform platform,
            long effectiveUid,
            UserPrincipal effectivePrincipal,
            UserPrincipal systemPrincipal,
            UserPrincipal administratorsPrincipal) {
    }

    private record CheckedPath(
            Path file,
            Path canonicalRoot,
            Path canonicalFile,
            BasicFileAttributes attributes) {
        private boolean sameIdentity(CheckedPath other) {
            if (!canonicalRoot.equals(other.canonicalRoot)
                    || !canonicalFile.equals(other.canonicalFile)
                    || attributes.size() != other.attributes.size()
                    || !attributes.creationTime().equals(other.attributes.creationTime())
                    || !attributes.lastModifiedTime().equals(other.attributes.lastModifiedTime())) {
                return false;
            }
            Object firstKey = attributes.fileKey();
            Object secondKey = other.attributes.fileKey();
            if (firstKey != null || secondKey != null) {
                return Objects.equals(firstKey, secondKey);
            }
            return true;
        }
    }

    private record CheckedDirectory(
            Path directory,
            Path canonical,
            BasicFileAttributes attributes) {
        private boolean sameIdentity(CheckedDirectory other) {
            if (!directory.equals(other.directory)
                    || !canonical.equals(other.canonical)
                    || !attributes.creationTime().equals(other.attributes.creationTime())
                    || !attributes.lastModifiedTime().equals(other.attributes.lastModifiedTime())) {
                return false;
            }
            Object firstKey = attributes.fileKey();
            Object secondKey = other.attributes.fileKey();
            if (firstKey != null || secondKey != null) {
                return Objects.equals(firstKey, secondKey);
            }
            return true;
        }
    }
}
