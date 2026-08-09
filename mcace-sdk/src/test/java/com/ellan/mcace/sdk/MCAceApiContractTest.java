package com.ellan.mcace.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.generated.TrustLevel;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.Method;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MCAceApiContractTest {
    private static final UUID PLAYER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID SESSION_ID = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID EVIDENCE_ID = UUID.fromString("00000000-0000-0000-0000-000000000003");
    private static final Instant NOW = Instant.ofEpochMilli(1_786_406_400_000L);

    @Test
    void snapshotOnlyImplementerRetainsSourceCompatibilityAndBaselineFeatures() {
        MCAceApi legacyImplementer = playerId -> Optional.of(snapshot());

        assertEquals(MCAceSdk.API_VERSION, legacyImplementer.descriptor().apiVersion());
        assertEquals(MCAceCapability.baseline(), legacyImplementer.descriptor().capabilities());
        assertTrue(legacyImplementer.isVerified(PLAYER_ID));
        assertEquals(TrustLevel.VERIFIED, legacyImplementer.trustLevel(PLAYER_ID));
        assertEquals(RiskBand.WATCH, legacyImplementer.risk(PLAYER_ID).orElseThrow().band());
        assertTrue(legacyImplementer.session(PLAYER_ID).isEmpty());
        assertEquals(EvidenceSummaryAvailability.NOT_SUPPORTED, legacyImplementer.evidence(PLAYER_ID).availability());
    }

    @Test
    void negotiationRequiresCompatibleMajorVersionAndEveryRequestedCapability() {
        MCAceSdkDescriptor offered = new MCAceSdkDescriptor(
                new MCAceSdkVersion(1, 2),
                EnumSet.of(MCAceCapability.PLAYER_SECURITY_SNAPSHOT, MCAceCapability.EVIDENCE_SUMMARY));

        MCAceSdkNegotiationResult compatible = new MCAceSdkNegotiationRequest(
                new MCAceSdkVersion(1, 1), SetFixtures.evidenceOnly()).evaluate(offered);
        MCAceSdkNegotiationResult missing = new MCAceSdkNegotiationRequest(
                new MCAceSdkVersion(1, 1), EnumSet.of(MCAceCapability.SESSION_SUMMARY)).evaluate(offered);
        MCAceSdkNegotiationResult wrongMajor = new MCAceSdkNegotiationRequest(
                new MCAceSdkVersion(2, 0), SetFixtures.evidenceOnly()).evaluate(offered);

        assertTrue(compatible.compatible());
        assertFalse(missing.compatible());
        assertEquals(EnumSet.of(MCAceCapability.SESSION_SUMMARY), missing.missingCapabilities());
        assertFalse(wrongMajor.compatible());
    }

    @Test
    void exportedInteropIsReadOnlyBoundedAndContentFree() {
        MCAceApi api = extendedApi();
        Function<Map<String, Object>, Map<String, Object>> exporter = MCAceInteropExports.from(api);
        Object provider = new Object() {
            @SuppressWarnings("unused")
            public Function<Map<String, Object>, Map<String, Object>> mcaceInteropV1() {
                return exporter;
            }
        };

        MCAceInteropBridge bridge = MCAceInterop.discover(provider).orElseThrow();
        assertTrue(bridge.negotiate(new MCAceSdkNegotiationRequest(
                MCAceSdk.API_VERSION,
                EnumSet.of(MCAceCapability.SESSION_SUMMARY, MCAceCapability.EVIDENCE_SUMMARY))).compatible());
        assertEquals("WATCH", bridge.snapshot(PLAYER_ID).orElseThrow().riskBand());
        assertEquals(SESSION_ID, bridge.session(PLAYER_ID).orElseThrow().sessionId());
        EvidenceSummary evidence = bridge.evidence(PLAYER_ID).summaries().getFirst();
        assertEquals(EVIDENCE_ID, evidence.evidenceId());
        assertTrue(evidence.clientReported());

        for (Method method : MCAceApi.class.getMethods()) {
            String name = method.getName().toLowerCase(java.util.Locale.ROOT);
            assertFalse(name.contains("ban") || name.contains("kick") || name.contains("punish"));
        }
        assertTrue(java.util.Arrays.stream(EvidenceSummary.class.getRecordComponents())
                .map(component -> component.getType())
                .noneMatch(type -> type == byte[].class
                        || type == java.nio.file.Path.class
                        || type == java.net.URI.class));
    }

    @Test
    void publicSummaryBoundariesRejectOversizedAndControlCharacterData() {
        List<RiskReason> oversized = java.util.stream.IntStream.range(0, 65)
                .mapToObj(index -> new RiskReason("R" + index, 1, "server", NOW, true))
                .toList();

        assertThrows(IllegalArgumentException.class, () -> new PlayerSecuritySnapshot(
                PLAYER_ID,
                TrustLevel.VERIFIED,
                AdmissionStatus.VERIFIED,
                1,
                RiskBand.NORMAL,
                "p1",
                NOW,
                oversized));
        assertThrows(IllegalArgumentException.class, () -> new RiskReason("BAD\nCODE", 1, "server", NOW, true));
    }

    @Test
    void reflectionDiscoveryDoesNotRequireSharedMCAceClassIdentity(@TempDir Path temporaryDirectory) throws Exception {
        Path source = temporaryDirectory.resolve("IsolatedProvider.java");
        Files.writeString(source, """
                import java.util.List;
                import java.util.Map;
                import java.util.function.Function;

                public final class IsolatedProvider {
                    public Function<Map<String, Object>, Map<String, Object>> mcaceInteropV1() {
                        return request -> {
                            Object operation = request.get("operation");
                            if ("descriptor".equals(operation)) {
                                return Map.of(
                                    "status", "ok",
                                    "api_major", 1,
                                    "api_minor", 0,
                                    "capabilities", List.of(
                                        "PLAYER_SECURITY_SNAPSHOT",
                                        "TRUST_SUMMARY",
                                        "RISK_SUMMARY"));
                            }
                            return Map.of("status", "not_found");
                        };
                    }
                }
                """, StandardCharsets.UTF_8);
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertTrue(compiler != null, "a JDK compiler is required for the class-loader contract test");
        assertEquals(0, compiler.run(null, null, null, "-d", temporaryDirectory.toString(), source.toString()));

        try (URLClassLoader isolatedLoader = new URLClassLoader(
                new URL[] {temporaryDirectory.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
            Object isolatedProvider = Class.forName("IsolatedProvider", true, isolatedLoader)
                    .getConstructor()
                    .newInstance();

            MCAceInteropBridge bridge = MCAceInterop.discover(isolatedProvider).orElseThrow();
            assertEquals(MCAceSdk.API_VERSION, bridge.descriptor().apiVersion());
            assertTrue(bridge.snapshot(PLAYER_ID).isEmpty());
        }
    }

    private static MCAceApi extendedApi() {
        return new MCAceApi() {
            @Override
            public Optional<PlayerSecuritySnapshot> snapshot(UUID playerId) {
                return PLAYER_ID.equals(playerId) ? Optional.of(MCAceApiContractTest.snapshot()) : Optional.empty();
            }

            @Override
            public MCAceSdkDescriptor descriptor() {
                return new MCAceSdkDescriptor(MCAceSdk.API_VERSION, EnumSet.allOf(MCAceCapability.class));
            }

            @Override
            public Optional<SessionSecuritySummary> session(UUID playerId) {
                return PLAYER_ID.equals(playerId)
                        ? Optional.of(new SessionSecuritySummary(
                                PLAYER_ID, SESSION_ID, SessionState.VERIFIED, TrustLevel.VERIFIED, NOW, NOW))
                        : Optional.empty();
            }

            @Override
            public EvidenceSummaryPage evidence(UUID playerId) {
                if (!PLAYER_ID.equals(playerId)) {
                    return new EvidenceSummaryPage(EvidenceSummaryAvailability.AVAILABLE, List.of());
                }
                return new EvidenceSummaryPage(EvidenceSummaryAvailability.AVAILABLE, List.of(new EvidenceSummary(
                        EVIDENCE_ID,
                        PLAYER_ID,
                        EvidenceType.GAME_RENDER_FRAME,
                        EvidenceState.VERIFIED,
                        true,
                        NOW,
                        NOW.plusSeconds(60))));
            }
        };
    }

    private static PlayerSecuritySnapshot snapshot() {
        return new PlayerSecuritySnapshot(
                PLAYER_ID,
                TrustLevel.VERIFIED,
                AdmissionStatus.VERIFIED,
                12,
                RiskBand.WATCH,
                "p1",
                NOW,
                List.of(new RiskReason("CLIENT_REPORT", 12, "fabric", NOW, false)));
    }

    private static final class SetFixtures {
        private SetFixtures() {
        }

        static java.util.Set<MCAceCapability> evidenceOnly() {
            return EnumSet.of(MCAceCapability.EVIDENCE_SUMMARY);
        }
    }
}
