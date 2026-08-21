package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class RuntimeProcessAssetsTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void resolvesOnlyExplicitHashPinnedAssetsAndExactWireIdentity() throws Exception {
        Fixture fixture = fixture();
        RuntimeProcessAssets assets = RuntimeProcessAssets.fromProperties(
                fixture.properties(), "PAPER", "VELOCITY");

        assertEquals("PAPER", assets.backendKind());
        assertEquals("VELOCITY", assets.proxyKind());
        assertEquals("1.21.11", assets.wireProfile().minecraftVersion());
        assertEquals(774, assets.wireProfile().protocolVersion());
        assertEquals(fixture.backendJar().toAbsolutePath().normalize(), assets.backendJar());
        assertEquals(fixture.preparedRoot().toAbsolutePath().normalize(), assets.preparedRoot());
        assertEquals(fixture.serverJava().toAbsolutePath().normalize(), assets.serverJava());
        assertEquals(fixture.proxyJar().toAbsolutePath().normalize(), assets.proxyJar());
    }

    @Test
    void rejectsMissingPropertiesHashDriftAndVersionProtocolMismatch() throws Exception {
        Fixture fixture = fixture();

        Properties missing = copy(fixture.properties());
        missing.remove("mcace.runtime.server-java");
        assertFailure(missing, "RUNTIME_PROPERTY_MISSING|mcace.runtime.server-java");

        Properties wrongHash = copy(fixture.properties());
        wrongHash.setProperty("mcace.runtime.backend.jar.sha256", "0".repeat(64));
        assertFailure(wrongHash, "RUNTIME_ASSET_SHA256_MISMATCH|");

        Properties wrongProtocol = copy(fixture.properties());
        wrongProtocol.setProperty("mcace.runtime.minecraft-protocol", "775");
        assertFailure(wrongProtocol, "RUNTIME_MINECRAFT_PROTOCOL_MISMATCH|");

        Properties wrongJava = copy(fixture.properties());
        wrongJava.setProperty("mcace.runtime.server-java-feature", "25");
        assertFailure(wrongJava, "RUNTIME_SERVER_JAVA_FEATURE_MISMATCH|");

        Properties wrongBackend = copy(fixture.properties());
        wrongBackend.setProperty("mcace.runtime.backend-kind", "FOLIA");
        assertFailure(wrongBackend, "RUNTIME_BACKEND_KIND_MISMATCH|");

        Properties legacyVersion = copy(fixture.properties());
        legacyVersion.setProperty("mcace.runtime.minecraft-version", "1.21.1");
        legacyVersion.setProperty("mcace.runtime.minecraft-protocol", "767");
        assertFailure(legacyVersion, "RUNTIME_MINECRAFT_VERSION_OUTSIDE_RELEASE_MATRIX|");
    }

    @Test
    void preparedRootDigestIsPathAndContentBound() throws Exception {
        Fixture fixture = fixture();
        String original = RuntimeProcessAssets.preparedTreeSha256(fixture.preparedRoot());
        Files.writeString(
                fixture.preparedRoot().resolve("libraries/example.bin"),
                "changed",
                StandardCharsets.UTF_8);
        String changedContent = RuntimeProcessAssets.preparedTreeSha256(fixture.preparedRoot());
        assertTrue(!original.equals(changedContent));

        Files.move(
                fixture.preparedRoot().resolve("libraries/example.bin"),
                fixture.preparedRoot().resolve("libraries/renamed.bin"));
        String changedPath = RuntimeProcessAssets.preparedTreeSha256(fixture.preparedRoot());
        assertTrue(!changedContent.equals(changedPath));

        String canonicalRoots = changedPath;
        Files.createDirectories(fixture.preparedRoot().resolve("world/DIM1"));
        Files.writeString(
                fixture.preparedRoot().resolve("world/DIM1/generated.dat"),
                "generated",
                StandardCharsets.US_ASCII);
        assertEquals(canonicalRoots, RuntimeProcessAssets.preparedTreeSha256(fixture.preparedRoot()));
    }

    @Test
    void foliaAcceptsTheModernSingleWorldPreparedLayout() throws Exception {
        Fixture fixture = fixture();
        Files.createDirectories(fixture.preparedRoot().resolve("world/DIM-1"));
        fixture.properties().setProperty("mcace.runtime.backend-kind", "FOLIA");
        fixture.properties().setProperty(
                "mcace.runtime.backend.prepared-root.sha256",
                RuntimeProcessAssets.preparedTreeSha256(fixture.preparedRoot()));

        RuntimeProcessAssets assets = RuntimeProcessAssets.fromProperties(
                fixture.properties(), "FOLIA", "VELOCITY");

        assertEquals("FOLIA", assets.backendKind());
        assertEquals(fixture.preparedRoot().toAbsolutePath().normalize(), assets.preparedRoot());
        assertFalse(Files.exists(fixture.preparedRoot().resolve("world_nether")));
        assertFalse(Files.exists(fixture.preparedRoot().resolve("world_the_end")));
    }

    private void assertFailure(Properties properties, String prefix) {
        IllegalArgumentException failure = assertThrows(
                IllegalArgumentException.class,
                () -> RuntimeProcessAssets.fromProperties(properties, "PAPER", "VELOCITY"));
        assertTrue(failure.getMessage().startsWith(prefix), failure::getMessage);
    }

    private Fixture fixture() throws Exception {
        Path backendJar = Files.writeString(
                temporaryDirectory.resolve("paper.jar"), "paper", StandardCharsets.US_ASCII);
        Path proxyJar = Files.writeString(
                temporaryDirectory.resolve("velocity.jar"), "velocity", StandardCharsets.US_ASCII);
        Path serverJava = Files.writeString(
                temporaryDirectory.resolve("java.exe"), "java", StandardCharsets.US_ASCII);
        Path preparedRoot = temporaryDirectory.resolve("prepared");
        Files.createDirectories(preparedRoot.resolve("cache"));
        Files.createDirectories(preparedRoot.resolve("libraries"));
        Files.createDirectories(preparedRoot.resolve("versions"));
        Files.writeString(
                preparedRoot.resolve("libraries/example.bin"), "library", StandardCharsets.US_ASCII);
        Files.writeString(
                preparedRoot.resolve("versions/version.jar"), "version", StandardCharsets.US_ASCII);

        Properties properties = new Properties();
        properties.setProperty("mcace.runtime.backend-kind", "PAPER");
        properties.setProperty("mcace.runtime.minecraft-version", "1.21.11");
        properties.setProperty("mcace.runtime.minecraft-protocol", "774");
        properties.setProperty("mcace.runtime.server-java-feature", "21");
        properties.setProperty("mcace.runtime.backend.jar", backendJar.toString());
        properties.setProperty(
                "mcace.runtime.backend.jar.sha256", RuntimeProcessAssets.sha256(backendJar));
        properties.setProperty("mcace.runtime.backend.prepared-root", preparedRoot.toString());
        properties.setProperty(
                "mcace.runtime.backend.prepared-root.sha256",
                RuntimeProcessAssets.preparedTreeSha256(preparedRoot));
        properties.setProperty("mcace.runtime.server-java", serverJava.toString());
        properties.setProperty(
                "mcace.runtime.server-java.sha256", RuntimeProcessAssets.sha256(serverJava));
        properties.setProperty("mcace.runtime.velocity.jar", proxyJar.toString());
        properties.setProperty(
                "mcace.runtime.velocity.jar.sha256", RuntimeProcessAssets.sha256(proxyJar));
        return new Fixture(properties, backendJar, preparedRoot, serverJava, proxyJar);
    }

    private static Properties copy(Properties properties) {
        Properties copy = new Properties();
        copy.putAll(properties);
        return copy;
    }

    private record Fixture(
            Properties properties,
            Path backendJar,
            Path preparedRoot,
            Path serverJava,
            Path proxyJar) { }
}
