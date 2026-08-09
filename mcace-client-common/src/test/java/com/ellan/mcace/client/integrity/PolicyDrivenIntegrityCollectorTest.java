package com.ellan.mcace.client.integrity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class PolicyDrivenIntegrityCollectorTest {
    @TempDir Path root;

    @Test
    void collectsAllowedScopesAndRepresentsMissingOptionalDirectory() throws Exception {
        Files.createDirectories(root.resolve("mods"));
        Files.writeString(root.resolve("mods").resolve("mcace.jar"), "trusted-test-artifact");
        Files.writeString(root.resolve("options.txt"), "fov:0.5");

        ClientIntegrityBundle bundle = collector().collect(root, policy(
                directory("mods", "mods", true, ".jar"),
                directory("resourcepacks", "resourcepacks", false, ".zip"),
                explicit("config", "options.txt")));

        assertEquals(3, bundle.scopes().size());
        assertTrue(bundle.scope("mods").orElseThrow().present());
        assertFalse(bundle.scope("resourcepacks").orElseThrow().present());
        assertEquals(1, bundle.scope("config").orElseThrow().entries().size());
    }

    @Test
    void refusesDirectoryOutsideMinecraftAllowlist() {
        SecurityPolicy request = policy(directory("private", "saves", false, ".dat"));

        assertThrows(IntegrityScanException.class, () -> collector().collect(root, request));
    }

    @Test
    void refusesExplicitFileWithoutLocalConsent() {
        SecurityPolicy request = policy(explicit("config", "config/sensitive.txt"));

        assertThrows(IntegrityScanException.class,
                () -> collector().collect(root, request, Set.of("options.txt")));
    }

    @Test
    void refusesExplicitPathEscapeEvenIfCallerConsents() {
        SecurityPolicy request = policy(explicit("config", "../outside.txt"));

        assertThrows(IntegrityScanException.class,
                () -> collector().collect(root, request, Set.of("../outside.txt")));
    }

    private PolicyDrivenIntegrityCollector collector() {
        return new PolicyDrivenIntegrityCollector(Clock.systemUTC());
    }

    private static SecurityPolicy policy(IntegrityScopeRule... rules) {
        return SecurityPolicy.newBuilder().addAllIntegrityScopes(java.util.List.of(rules)).build();
    }

    private static IntegrityScopeRule directory(String scope, String root, boolean required, String extension) {
        return IntegrityScopeRule.newBuilder().setScope(scope).setRelativeRoot(root).setRequired(required)
                .setMaxEntries(16).setMaxFileBytes(1024 * 1024).addAllowedExtensions(extension).build();
    }

    private static IntegrityScopeRule explicit(String scope, String path) {
        return IntegrityScopeRule.newBuilder().setScope(scope).setRequired(false)
                .setMaxEntries(4).setMaxFileBytes(1024 * 1024).addAllowedExtensions(".txt")
                .addExplicitRelativeFiles(path).build();
    }
}
