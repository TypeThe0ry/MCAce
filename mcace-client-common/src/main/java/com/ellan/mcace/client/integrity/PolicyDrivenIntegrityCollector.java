package com.ellan.mcace.client.integrity;

import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class PolicyDrivenIntegrityCollector {
    private static final Set<String> ALLOWED_DIRECTORY_ROOTS = Set.of("mods", "resourcepacks", "shaderpacks");
    private static final Set<String> DEFAULT_CONSENTED_FILES = Set.of("options.txt");
    private final Clock clock;
    private final ScopedIntegrityScanner scanner;

    public PolicyDrivenIntegrityCollector(Clock clock) {
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
        this.scanner = new ScopedIntegrityScanner(clock);
    }

    public ClientIntegrityBundle collect(Path minecraftRoot, SecurityPolicy policy) throws IntegrityScanException {
        return collect(minecraftRoot, policy, DEFAULT_CONSENTED_FILES);
    }

    public ClientIntegrityBundle collect(
            Path minecraftRoot,
            SecurityPolicy policy,
            Set<String> consentedExplicitFiles) throws IntegrityScanException {
        Set<String> consented = consentedExplicitFiles.stream()
                .map(path -> path.replace('\\', '/'))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        List<ScopeIntegrityManifest> manifests = new ArrayList<>();
        for (IntegrityScopeRule rule : policy.getIntegrityScopesList()) {
            ScanPolicy scanPolicy = new ScanPolicy(
                    rule.getMaxEntries(),
                    rule.getMaxFileBytes(),
                    new HashSet<>(rule.getAllowedExtensionsList()));
            String scopeName = rule.getScope().toLowerCase(Locale.ROOT);
            if (rule.getExplicitRelativeFilesCount() > 0) {
                if (!consented.containsAll(rule.getExplicitRelativeFilesList())) {
                    throw new IntegrityScanException("policy requests explicit files without local consent");
                }
                manifests.add(scanner.scanExplicitFiles(
                        minecraftRoot,
                        scopeName,
                        rule.getExplicitRelativeFilesList(),
                        scanPolicy,
                        rule.getRequired()));
                continue;
            }
            if (!ALLOWED_DIRECTORY_ROOTS.contains(rule.getRelativeRoot())) {
                throw new IntegrityScanException("policy requests a forbidden directory scope: " + rule.getRelativeRoot());
            }
            Path relativeRoot = Path.of(rule.getRelativeRoot());
            Path directory = minecraftRoot.toAbsolutePath().normalize().resolve(relativeRoot).normalize();
            if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                if (rule.getRequired()) {
                    throw new IntegrityScanException("required integrity scope is missing: " + scopeName);
                }
                manifests.add(new ScopeIntegrityManifest(
                        scopeName,
                        rule.getRelativeRoot(),
                        false,
                        clock.instant(),
                        List.of(),
                        ScopedIntegrityScanner.manifestRoot(List.of())));
                continue;
            }
            IntegrityManifest scanned = scanner.scan(minecraftRoot, relativeRoot, scanPolicy);
            manifests.add(new ScopeIntegrityManifest(
                    scopeName,
                    rule.getRelativeRoot(),
                    true,
                    scanned.capturedAt(),
                    scanned.entries(),
                    scanned.rootSha256()));
        }
        return ClientIntegrityBundle.of(manifests);
    }
}
