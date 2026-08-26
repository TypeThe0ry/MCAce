package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.core.session.AuthenticatedManifest;
import com.ellan.mcace.protocol.generated.FileEntry;
import com.ellan.mcace.protocol.generated.IntegrityScopeManifest;
import com.ellan.mcace.protocol.generated.LoadedModEntry;
import com.ellan.mcace.protocol.generated.LoadedModOriginKind;
import com.ellan.mcace.protocol.generated.ModEntry;
import com.ellan.mcace.protocol.integrity.IntegrityDigests;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Derives all initial artifact observations from the authenticated integrity-scope entries.
 * Client-provided mod id/version/signer metadata is attached only after an exact filename/size/hash
 * reconciliation with a mods-scope entry. Origin, confidence, and foundation status are fixed by
 * this server-side code and never accepted from the client.
 */
public final class AuthenticatedManifestObservationDeriver {
    private static final int MAX_DERIVED_OBSERVATIONS = 16_384;
    private static final int MAX_IDENTIFIER_CHARS = 128;
    private static final int MAX_PATH_CHARS = 512;
    private static final int MAX_PATH_SEGMENT_CHARS = 128;
    private static final int MAX_DIRECTORY_GROUPS = 4_096;
    private static final int MAX_DIRECTORY_ENTRIES = 16_384;

    public AuthenticatedManifestDerivation derive(AuthenticatedManifest manifest) {
        Objects.requireNonNull(manifest, "manifest");
        Map<ModFingerprint, List<ModEntry>> mods = indexMods(manifest.request().getModsList());
        List<ArtifactObservation> observations = new ArrayList<>();
        List<String> issues = new ArrayList<>();
        LoadedModIndex loadedMods = indexLoadedMods(manifest.request().getLoadedModsList(), issues);
        if (manifest.request().getLoadedModsCount() == 0) issues.add("loaded-mod-list-empty");
        Map<DirectoryGroupKey, List<FileEntry>> directoryGroups = new HashMap<>();
        Set<DirectoryGroupKey> invalidDirectoryGroups = new HashSet<>();
        int directoryEntries = 0;
        for (IntegrityScopeManifest scope : manifest.request().getScopeManifestsList()) {
            ArtifactType type = typeFor(scope.getScope());
            if (type == null || !scope.getPresent()) continue;
            Set<String> seenPaths = new HashSet<>();
            for (FileEntry entry : scope.getEntriesList()) {
                if (observations.size() == MAX_DERIVED_OBSERVATIONS) {
                    issues.add("derived-observation-limit");
                    return result(observations, issues);
                }
                if (!validFileEntry(entry)) {
                    issues.add("invalid-scope-entry");
                    continue;
                }
                if (!seenPaths.add(entry.getRelativePath())) {
                    issues.add("duplicate-scope-path");
                    if (type == ArtifactType.RESOURCE_PACK || type == ArtifactType.SHADER_PACK) {
                        DirectoryPath duplicatePath = directoryPath(entry.getRelativePath());
                        if (duplicatePath.directory()) {
                            DirectoryGroupKey key = new DirectoryGroupKey(type, scope.getScope(),
                                    duplicatePath.topLevel());
                            invalidDirectoryGroups.add(key);
                            directoryGroups.remove(key);
                            issues.add("duplicate-rebased-path");
                        }
                    }
                    continue;
                }
                if (type == ArtifactType.MOD) {
                    observations.add(modObservation(entry, mods, loadedMods, issues));
                } else {
                    observations.add(scopeObservation(
                            type,
                            scope.getScope(),
                            entry,
                            selectedForEntry(type, entry.getRelativePath(),
                                    manifest.request().getSelectedResourcePacksList(),
                                    manifest.request().getSelectedShaderPacksList())));
                    if (type == ArtifactType.RESOURCE_PACK || type == ArtifactType.SHADER_PACK) {
                        DirectoryPath directoryPath = directoryPath(entry.getRelativePath());
                        if (directoryPath.invalid()) {
                            issues.add(directoryPath.issue());
                        } else if (directoryPath.directory()) {
                            DirectoryGroupKey key = new DirectoryGroupKey(type, scope.getScope(),
                                    directoryPath.topLevel());
                            if (invalidDirectoryGroups.contains(key)) continue;
                            List<FileEntry> group = directoryGroups.get(key);
                            if (group == null) {
                                if (directoryGroups.size() >= MAX_DIRECTORY_GROUPS) {
                                    issues.add("directory-group-limit");
                                } else {
                                    group = new ArrayList<>();
                                    directoryGroups.put(key, group);
                                }
                            }
                            if (group != null) {
                                if (directoryEntries >= MAX_DIRECTORY_ENTRIES) {
                                    issues.add("directory-entry-limit");
                                } else {
                                    group.add(entry.toBuilder()
                                            .setRelativePath(directoryPath.rebasedPath()).build());
                                    directoryEntries++;
                                }
                            }
                        }
                    }
                }
            }
        }
        for (List<ModEntry> unmatched : mods.values()) {
            for (int index = 0; index < unmatched.size(); index++) issues.add("mod-list-without-scope-entry");
        }
        appendRuntimeLoadedModObservations(loadedMods, observations, issues);
        appendDirectoryPackageObservations(
                directoryGroups,
                manifest.request().getSelectedResourcePacksList(),
                manifest.request().getSelectedShaderPacksList(),
                observations,
                issues);
        return result(observations, issues);
    }

    private static void appendDirectoryPackageObservations(
            Map<DirectoryGroupKey, List<FileEntry>> groups,
            List<String> selectedResourcePacks,
            List<String> selectedShaderPacks,
            List<ArtifactObservation> observations,
            List<String> issues) {
        for (Map.Entry<DirectoryGroupKey, List<FileEntry>> grouped : groups.entrySet().stream()
                .sorted(Map.Entry.comparingByKey()).toList()) {
            if (observations.size() == MAX_DERIVED_OBSERVATIONS) {
                issues.add("derived-observation-limit");
                return;
            }
            List<FileEntry> entries = grouped.getValue().stream()
                    .sorted(Comparator.comparing(FileEntry::getRelativePath)).toList();
            Set<String> paths = new HashSet<>();
            if (entries.isEmpty() || entries.stream().anyMatch(entry -> !paths.add(entry.getRelativePath()))) {
                issues.add("duplicate-rebased-path");
                continue;
            }
            try {
                String root = hex(IntegrityDigests.scopeRoot(entries));
                DirectoryGroupKey key = grouped.getKey();
                boolean selected = isSelected(key, selectedResourcePacks, selectedShaderPacks);
                Map<String, String> metadata = Map.of(
                        "scope", key.scope(),
                        "package_kind", "directory",
                        "content_root_sha256", root,
                        "selected", Boolean.toString(selected));
                observations.add(observation(key.type(), directoryIdentifier(key.type(), root),
                        "unknown", null, metadata));
            } catch (IllegalArgumentException exception) {
                issues.add("invalid-directory-content-root");
            }
        }
    }

    private static boolean isSelected(
            DirectoryGroupKey key, List<String> selectedResourcePacks, List<String> selectedShaderPacks) {
        List<String> selected = key.type() == ArtifactType.RESOURCE_PACK
                ? selectedResourcePacks : selectedShaderPacks;
        String topLevel = key.topLevel();
        return selected.stream().anyMatch(id -> id.equals(topLevel)
                || id.equals("file/" + topLevel)
                || id.endsWith("/" + topLevel));
    }

    private static AuthenticatedManifestDerivation result(
            List<ArtifactObservation> observations, List<String> issues) {
        observations.sort(Comparator.comparing((ArtifactObservation observation) -> observation.type().name())
                .thenComparing(ArtifactObservation::identifier)
                .thenComparing(ArtifactObservation::sha256, Comparator.nullsFirst(String::compareTo)));
        return new AuthenticatedManifestDerivation(observations, issues.stream().limit(128).toList());
    }

    private static Map<ModFingerprint, List<ModEntry>> indexMods(List<ModEntry> entries) {
        Map<ModFingerprint, List<ModEntry>> result = new HashMap<>();
        for (ModEntry entry : entries) {
            if (entry.getFilename().isBlank() || entry.getSha256().size() != 32) continue;
            result.computeIfAbsent(new ModFingerprint(entry.getFilename(), entry.getFileSize(), hex(entry.getSha256().toByteArray())),
                    ignored -> new ArrayList<>()).add(entry);
        }
        return result;
    }

    private static ArtifactObservation modObservation(
            FileEntry entry,
            Map<ModFingerprint, List<ModEntry>> mods,
            LoadedModIndex loadedMods,
            List<String> issues) {
        ModFingerprint fingerprint = new ModFingerprint(entry.getRelativePath(), entry.getFileSize(), hex(entry.getSha256().toByteArray()));
        List<ModEntry> matches = mods.remove(fingerprint);
        if (matches == null || matches.size() != 1 || matches.getFirst().getId().isBlank()
                || matches.getFirst().getVersion().isBlank() || matches.getFirst().getId().length() > MAX_IDENTIFIER_CHARS
                || matches.getFirst().getVersion().length() > MAX_IDENTIFIER_CHARS) {
            if (matches != null && matches.size() > 1) issues.add("ambiguous-mod-list-entry");
            else issues.add("mods-scope-entry-without-matching-mod-list-entry");
            return observation(ArtifactType.MOD, "unknown:" + fingerprint.sha256(), "unknown",
                    fingerprint.sha256(), Map.of("scope", "mods", "artifact_path",
                            entry.getRelativePath(), "loaded", "false",
                            "origin_manifest_matched", "false"));
        }
        ModEntry mod = matches.getFirst();
        // signer and metadata are self-reported client strings; never feed them into selectors.
        LoadedModKey loadedKey = new LoadedModKey(mod.getId(), mod.getVersion());
        LoadedModEntry loaded = loadedMods.byIdentity().get(loadedKey);
        boolean runtimeMatched = loaded != null && loaded.getOriginManifestMatched()
                && loaded.getOriginKind() == LoadedModOriginKind.LOADED_MOD_ORIGIN_MODS_FILE
                && loaded.getOriginFilename().equals(entry.getRelativePath())
                && loaded.getOriginFileSize() == entry.getFileSize()
                && java.security.MessageDigest.isEqual(
                        loaded.getOriginSha256().toByteArray(), entry.getSha256().toByteArray());
        if (runtimeMatched) loadedMods.consumed().add(loadedKey);
        Map<String, String> metadata = Map.of(
                "scope", "mods",
                "artifact_path", entry.getRelativePath(),
                "loaded", Boolean.toString(runtimeMatched),
                "loaded_origin", runtimeMatched ? "mods_file" : "not_reported_loaded",
                "origin_manifest_matched", Boolean.toString(runtimeMatched));
        return observation(ArtifactType.MOD, mod.getId(), mod.getVersion(), fingerprint.sha256(), metadata);
    }

    private static LoadedModIndex indexLoadedMods(List<LoadedModEntry> entries, List<String> issues) {
        Map<LoadedModKey, LoadedModEntry> byIdentity = new LinkedHashMap<>();
        for (LoadedModEntry entry : entries) {
            LoadedModKey key = new LoadedModKey(entry.getId(), entry.getVersion());
            if (byIdentity.putIfAbsent(key, entry) != null) issues.add("duplicate-loaded-mod-identity");
        }
        return new LoadedModIndex(Map.copyOf(byIdentity), new HashSet<>());
    }

    private static void appendRuntimeLoadedModObservations(
            LoadedModIndex loadedMods, List<ArtifactObservation> observations, List<String> issues) {
        for (Map.Entry<LoadedModKey, LoadedModEntry> indexed : loadedMods.byIdentity().entrySet().stream()
                .sorted(Map.Entry.comparingByKey()).toList()) {
            if (loadedMods.consumed().contains(indexed.getKey())) continue;
            if (observations.size() == MAX_DERIVED_OBSERVATIONS) {
                issues.add("derived-observation-limit");
                return;
            }
            LoadedModEntry loaded = indexed.getValue();
            if (loaded.getOriginManifestMatched()) {
                issues.add("loaded-mod-manifest-binding-not-consumed");
            } else if (loaded.getOriginKind() == LoadedModOriginKind.LOADED_MOD_ORIGIN_MODS_FILE) {
                issues.add("loaded-mod-origin-without-manifest-match");
            }
            Map<String, String> metadata = new LinkedHashMap<>();
            metadata.put("scope", "fabric-runtime");
            metadata.put("loaded", "true");
            metadata.put("loaded_origin", loadedOrigin(loaded.getOriginKind()));
            metadata.put("origin_manifest_matched", Boolean.toString(loaded.getOriginManifestMatched()));
            if (!loaded.getOriginFilename().isEmpty()) {
                metadata.put("origin_filename", loaded.getOriginFilename());
            }
            if (!loaded.getParentModId().isEmpty()) {
                metadata.put("parent_mod_id", loaded.getParentModId());
            }
            observations.add(observation(ArtifactType.MOD, loaded.getId(), loaded.getVersion(),
                    loaded.getOriginManifestMatched() && loaded.getOriginSha256().size() == 32
                            ? hex(loaded.getOriginSha256().toByteArray()) : null,
                    Map.copyOf(metadata)));
        }
    }

    private static String loadedOrigin(LoadedModOriginKind origin) {
        return switch (origin) {
            case LOADED_MOD_ORIGIN_MODS_FILE -> "mods_file";
            case LOADED_MOD_ORIGIN_NESTED -> "nested";
            case LOADED_MOD_ORIGIN_BUILTIN_OR_CLASSPATH -> "builtin_or_classpath";
            case LOADED_MOD_ORIGIN_UNKNOWN, LOADED_MOD_ORIGIN_UNSPECIFIED, UNRECOGNIZED -> "unknown";
        };
    }

    private static ArtifactObservation scopeObservation(
            ArtifactType type, String scope, FileEntry entry, boolean selected) {
        return observation(type, entry.getRelativePath(), "unknown", hex(entry.getSha256().toByteArray()),
                Map.of("scope", scope, "artifact_path", entry.getRelativePath(),
                        "selected", Boolean.toString(selected)));
    }

    private static boolean selectedForEntry(
            ArtifactType type,
            String path,
            List<String> selectedResourcePacks,
            List<String> selectedShaderPacks) {
        List<String> selected = type == ArtifactType.RESOURCE_PACK
                ? selectedResourcePacks : selectedShaderPacks;
        String topLevel = path;
        int separator = path.indexOf('/');
        if (separator > 0) topLevel = path.substring(0, separator);
        String candidate = topLevel;
        return selected.stream().anyMatch(id -> id.equals(path)
                || id.equals(candidate)
                || id.equals("file/" + candidate)
                || id.endsWith("/" + candidate));
    }

    private static boolean validFileEntry(FileEntry entry) {
        return entry.getFileSize() >= 0 && entry.getSha256().size() == 32
                && safeRelativePath(entry.getRelativePath());
    }

    private static DirectoryPath directoryPath(String path) {
        int separator = path.indexOf('/');
        if (separator < 0) return DirectoryPath.noDirectory();
        if (separator == 0 || separator == path.length() - 1) {
            return DirectoryPath.invalid("invalid-directory-top-level");
        }
        String topLevel = path.substring(0, separator);
        String rebased = path.substring(separator + 1);
        if (!safePathSegment(topLevel) || !safeRelativePath(rebased)) {
            return DirectoryPath.invalid("invalid-directory-rebased-path");
        }
        return DirectoryPath.directory(topLevel, rebased);
    }

    private static boolean safeRelativePath(String path) {
        if (path == null || path.isBlank() || path.length() > MAX_PATH_CHARS
                || path.startsWith("/") || path.endsWith("/") || path.contains("\\")
                || path.contains(":") || path.chars().anyMatch(Character::isISOControl)) {
            return false;
        }
        String[] segments = path.split("/", -1);
        for (String segment : segments) {
            if (!safePathSegment(segment)) return false;
        }
        return true;
    }

    private static boolean safePathSegment(String segment) {
        return segment != null && !segment.isBlank() && !segment.equals(".")
                && !segment.equals("..") && segment.length() <= MAX_PATH_SEGMENT_CHARS
                && segment.chars().noneMatch(Character::isISOControl);
    }

    private static String directoryIdentifier(ArtifactType type, String root) {
        String identifier = "directory:" + type.name().toLowerCase(Locale.ROOT) + ":" + root;
        if (identifier.length() > MAX_IDENTIFIER_CHARS) {
            throw new IllegalStateException("directory observation identifier exceeds bounds");
        }
        return identifier;
    }

    private static ArtifactObservation observation(
            ArtifactType type, String identifier, String version, String sha256, Map<String, String> metadata) {
        return new ArtifactObservation(type, identifier, version, sha256, metadata,
                ObservationOrigin.CLIENT_REPORTED, Confidence.LOW, false);
    }

    private static ArtifactType typeFor(String scope) {
        return switch (scope.toLowerCase(Locale.ROOT)) {
            case "mods" -> ArtifactType.MOD;
            case "resourcepacks" -> ArtifactType.RESOURCE_PACK;
            case "shaderpacks" -> ArtifactType.SHADER_PACK;
            case "config" -> ArtifactType.CONFIG;
            default -> null;
        };
    }

    private static String hex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    private record ModFingerprint(String filename, long fileSize, String sha256) { }

    private record LoadedModKey(String id, String version) implements Comparable<LoadedModKey> {
        @Override
        public int compareTo(LoadedModKey other) {
            int idOrder = id.compareTo(other.id);
            return idOrder != 0 ? idOrder : version.compareTo(other.version);
        }
    }

    private record LoadedModIndex(
            Map<LoadedModKey, LoadedModEntry> byIdentity, Set<LoadedModKey> consumed) { }

    private record DirectoryGroupKey(ArtifactType type, String scope, String topLevel)
            implements Comparable<DirectoryGroupKey> {
        @Override
        public int compareTo(DirectoryGroupKey other) {
            int typeOrder = type.compareTo(other.type);
            if (typeOrder != 0) return typeOrder;
            int scopeOrder = scope.compareTo(other.scope);
            if (scopeOrder != 0) return scopeOrder;
            return topLevel.compareTo(other.topLevel);
        }
    }

    private record DirectoryPath(boolean directory, String topLevel, String rebasedPath, String issue) {
        private static DirectoryPath noDirectory() {
            return new DirectoryPath(false, "", "", "");
        }

        private static DirectoryPath directory(String topLevel, String rebasedPath) {
            return new DirectoryPath(true, topLevel, rebasedPath, "");
        }

        private static DirectoryPath invalid(String issue) {
            return new DirectoryPath(false, "", "", issue);
        }

        private boolean invalid() {
            return !issue.isEmpty();
        }
    }
}
