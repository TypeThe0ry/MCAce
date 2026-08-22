package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.EvidenceSummaryAvailability;
import com.ellan.mcace.sdk.MCAceApi;
import com.ellan.mcace.sdk.MCAceCapability;
import com.ellan.mcace.sdk.MCAceInterop;
import com.ellan.mcace.sdk.MCAceInteropException;
import com.ellan.mcace.sdk.MCAceInteropExports;
import com.ellan.mcace.sdk.MCAceSdkVersion;
import com.ellan.mcace.sdk.MCAceSdkNegotiationRequest;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import com.ellan.mcace.sdk.RiskReason;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.lang.reflect.Modifier;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * Platform-neutral contract for the public third-party SDK boundary.
 *
 * <p>The deployed proxy/backend adapters have independent plugin class loaders.  This test
 * deliberately inspects the produced artifacts instead of inferring a shared Java type identity
 * from Gradle's test class path.  It also locks the current SDK to read-only, content-free
 * snapshots while the JDK-only reflective bridge migration is rolled out.
 */
final class SdkCompatibilityContractTest {
    private static final UUID PLAYER_ID = UUID.fromString("4b9c2ba2-292a-455a-b4e4-c7852c3fe6b2");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-09T00:00:00Z");
    private static final Set<Class<?>> FORBIDDEN_TYPES = Set.of(
            byte[].class, ByteBuffer.class, Path.class, File.class, InputStream.class,
            OutputStream.class, Key.class);

    @Test
    void snapshotsAreImmutableAndDefaultQueriesRemainReadOnly() {
        List<RiskReason> mutableReasons = new ArrayList<>();
        mutableReasons.add(new RiskReason("MOD_MANIFEST_MISMATCH", 50, "fabric-mod", EVALUATED_AT, false));
        PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                PLAYER_ID, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 50,
                RiskBand.RESTRICTED, "policy-2026-08-09", EVALUATED_AT, mutableReasons);
        mutableReasons.clear();

        assertEquals(1, snapshot.reasons().size());
        assertThrows(UnsupportedOperationException.class, () -> snapshot.reasons().add(
                new RiskReason("OTHER", 0, "test", EVALUATED_AT, false)));

        InMemoryMCAceApi api = new InMemoryMCAceApi();
        assertFalse(api.snapshot(PLAYER_ID).isPresent());
        assertFalse(api.isVerified(PLAYER_ID));
        assertEquals(TrustLevel.UNKNOWN, api.trustLevel(PLAYER_ID));
        assertEquals(0, api.riskScore(PLAYER_ID));

        api.publish(snapshot);
        assertEquals(snapshot, api.snapshot(PLAYER_ID).orElseThrow());
        assertTrue(api.isVerified(PLAYER_ID));
        assertEquals(TrustLevel.VERIFIED, api.trustLevel(PLAYER_ID));
        assertEquals(50, api.riskScore(PLAYER_ID));
    }

    @Test
    void versionNegotiationAndEvidenceDefaultsAreReadOnlyAndContentFree() {
        MCAceApi api = new InMemoryMCAceApi();
        var offered = api.descriptor();
        assertEquals(new MCAceSdkVersion(1, 0), offered.apiVersion());
        assertTrue(offered.supports(MCAceCapability.baseline()));
        var compatible = api.negotiate(new MCAceSdkNegotiationRequest(
                new MCAceSdkVersion(1, 0), MCAceCapability.baseline()));
        assertTrue(compatible.compatible());
        assertTrue(compatible.missingCapabilities().isEmpty());
        assertEquals(EvidenceSummaryAvailability.NOT_SUPPORTED, api.evidence(PLAYER_ID).availability());
        assertTrue(api.evidence(PLAYER_ID).summaries().isEmpty());
    }

    @Test
    void jdkOnlyInteropDiscoversReadOnlySnapshotAndRejectsRawPayloadValues() {
        InMemoryMCAceApi api = new InMemoryMCAceApi();
        api.publish(new PlayerSecuritySnapshot(
                PLAYER_ID, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0,
                RiskBand.NORMAL, "policy-2026-08-09", EVALUATED_AT, List.of()));
        var bridge = MCAceInterop.discover(new InteropProvider(api)).orElseThrow();

        assertEquals(new MCAceSdkVersion(1, 0), bridge.descriptor().apiVersion());
        assertEquals(PLAYER_ID, bridge.snapshot(PLAYER_ID).orElseThrow().playerId());
        assertEquals("VERIFIED", bridge.snapshot(PLAYER_ID).orElseThrow().trustLevel());
        assertTrue(bridge.session(PLAYER_ID).isEmpty());
        assertEquals(EvidenceSummaryAvailability.NOT_SUPPORTED, bridge.evidence(PLAYER_ID).availability());

        var malformed = MCAceInterop.discover(new MalformedInteropProvider()).orElseThrow();
        assertThrows(MCAceInteropException.class, malformed::descriptor,
                "byte arrays must never cross the reflective third-party boundary");
    }

    @Test
    void publicSdkSurfaceCannotExposeRawEvidenceKeysOrPrivateStorageHandles() throws Exception {
        for (Class<?> type : sdkSurface()) {
            for (var field : type.getDeclaredFields()) {
                if (!Modifier.isPublic(field.getModifiers())) {
                    continue;
                }
                assertSafeType(type, field.getType(), "public field " + field.getName());
                assertNoSensitiveName(type, field.getName());
            }
            for (var method : type.getDeclaredMethods()) {
                if (!Modifier.isPublic(method.getModifiers())) {
                    continue;
                }
                assertSafeType(type, method.getReturnType(), "return type of " + method.getName());
                for (Class<?> parameter : method.getParameterTypes()) {
                    assertSafeType(type, parameter, "parameter of " + method.getName());
                }
                assertNoSensitiveName(type, method.getName());
            }
            if (type.isRecord()) {
                for (var component : type.getRecordComponents()) {
                    assertSafeType(type, component.getType(), "record component " + component.getName());
                    assertNoSensitiveName(type, component.getName());
                }
            }
        }
    }

    @Test
    void packagedAdaptersProveWhyThirdPartiesCannotAssumeSharedSdkClassIdentity() throws Exception {
        for (AdapterJar adapter : adapters()) {
            try (JarFile jar = new JarFile(adapter.path().toFile())) {
                assertTrue(jar.getEntry("com/ellan/mcace/sdk/MCAceApi.class") != null,
                        () -> adapter.name() + " must be inspected as the actual deployed shadow jar");
                assertTrue(jar.getEntry(adapter.descriptor()) != null,
                        () -> adapter.name() + " deployment descriptor missing");
                if (adapter.serviceResource() != null) {
                    // Git/Gradle may preserve the platform line ending when the adapter is
                    // packaged on Windows.  ServiceLoader accepts either form; compare the
                    // semantic provider entry rather than making the cross-platform artifact
                    // gate depend on CRLF vs LF.
                    assertEquals(adapter.serviceProvider() + "\n",
                            readUtf8(jar, adapter.serviceResource()).replace("\r\n", "\n"));
                }
            }
            try (URLClassLoader isolated = new URLClassLoader(
                    new URL[] {adapter.path().toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
                Class<?> isolatedApi = Class.forName(MCAceApi.class.getName(), false, isolated);
                assertNotSame(MCAceApi.class, isolatedApi,
                        () -> adapter.name() + " embeds a private SDK class identity");
                assertEquals(MCAceApi.class.getName(), isolatedApi.getName());
            }
        }
    }

    private static void assertSafeType(Class<?> owner, Class<?> type, String position) {
        for (Class<?> forbidden : FORBIDDEN_TYPES) {
            assertFalse(forbidden.isAssignableFrom(type),
                    () -> owner.getName() + " must not expose " + forbidden.getName() + " as " + position);
        }
        assertFalse(type.getName().startsWith("java.security."),
                () -> owner.getName() + " must not expose security material as " + position);
    }

    private static void assertNoSensitiveName(Class<?> owner, String memberName) {
        String lower = memberName.toLowerCase(java.util.Locale.ROOT);
        for (String prohibited : List.of("screenshot", "image", "private", "storage", "path", "key")) {
            assertFalse(lower.contains(prohibited),
                    () -> owner.getName() + " must not expose a sensitive SDK member: " + memberName);
        }
    }

    private static List<AdapterJar> adapters() throws java.io.IOException {
        Path root = findRepositoryRoot();
        return List.of(
                adapter(root, "Paper/Folia", "mcace-server-paper", "plugin.yml", null, null),
                adapter(root, "Velocity", "mcace-server-velocity", "velocity-plugin.json", null, null),
                adapter(root, "BungeeCord", "mcace-server-bungeecord", "bungee.yml",
                        "META-INF/services/com.ellan.mcace.bungeecord.BungeeSessionBridgeFactory",
                        "com.ellan.mcace.bungeecord.LocalBungeeSessionBridgeFactory"));
    }

    private static List<Class<?>> sdkSurface() throws Exception {
        Path sourceDirectory = findRepositoryRoot().resolve("mcace-sdk/src/main/java/com/ellan/mcace/sdk");
        try (var paths = Files.list(sourceDirectory)) {
            List<Class<?>> types = new ArrayList<>();
            for (Path source : paths.filter(path -> path.getFileName().toString().endsWith(".java")).toList()) {
                String simpleName = source.getFileName().toString().replaceFirst("\\.java$", "");
                Class<?> type = Class.forName("com.ellan.mcace.sdk." + simpleName, false, MCAceApi.class.getClassLoader());
                if (Modifier.isPublic(type.getModifiers())) {
                    types.add(type);
                }
            }
            return List.copyOf(types);
        }
    }

    private static AdapterJar adapter(
            Path root, String name, String project, String descriptor, String serviceResource, String serviceProvider)
            throws java.io.IOException {
        try (var paths = Files.list(root.resolve(project).resolve("build/libs"))) {
            Path jar = paths.filter(path -> {
                        String file = path.getFileName().toString();
                        return file.endsWith(".jar") && !file.contains("-plain") && !file.contains("-sources");
                    })
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(name + " shadow jar was not built"));
            return new AdapterJar(name, jar, descriptor, serviceResource, serviceProvider);
        }
    }

    private static Path findRepositoryRoot() {
        Path current = Path.of("").toAbsolutePath().normalize();
        while (current != null && !Files.isRegularFile(current.resolve("settings.gradle.kts"))) {
            current = current.getParent();
        }
        if (current == null) {
            throw new IllegalStateException("could not locate MCAce repository root");
        }
        return current;
    }

    private static String readUtf8(JarFile jar, String entryName) throws java.io.IOException {
        JarEntry entry = jar.getJarEntry(entryName);
        if (entry == null) {
            throw new IllegalStateException("missing service resource " + entryName);
        }
        try (InputStream input = jar.getInputStream(entry)) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** Mimics the future public provider method without sharing any MCAce type across it. */
    public static final class InteropProvider {
        private final MCAceApi api;

        public InteropProvider(MCAceApi api) {
            this.api = api;
        }

        public Function<Map<String, Object>, Map<String, Object>> mcaceInteropV1() {
            return MCAceInteropExports.from(api);
        }
    }

    /** Deliberately violates the map contract with a raw byte array. */
    public static final class MalformedInteropProvider {
        public Function<Map<String, Object>, Map<String, Object>> mcaceInteropV1() {
            return ignored -> Map.of(
                    MCAceInterop.STATUS, MCAceInterop.STATUS_OK,
                    "api_major", 1,
                    "api_minor", 0,
                    "capabilities", List.of(new byte[] {1}));
        }
    }

    private record AdapterJar(String name, Path path, String descriptor, String serviceResource, String serviceProvider) { }
}
