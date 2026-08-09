package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/** Pure checks for the Bungee Phase-2 report/evidence boundary; no proxy process is started. */
final class BungeeDispositionPhaseTwoLogicTest {
    @Test
    void monitorRequiresOnlyVerifiedLobbyAndNoRouteLifecycleMarkers() {
        var outcome = outcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.MONITOR_LIMIT,
                false, false, false, MinecraftProxyPlayerProbeTest.RouteCompletion.NONE,
                true, false, false);

        assertTrue(outcome.passed());
        String report = RealProxyDispositionMatrixGateTest.phaseTwoBungeeJson(outcome);
        assertTrue(report.contains("\"platform\": \"BUNGEE\""));
        assertTrue(report.contains("\"publisher_gate\": \"ACTIVE\""));
        assertTrue(report.contains("\"server_hello_stage\": \"CONFIGURATION\""));
        assertTrue(report.contains("\"remote_liveness\": \"QUIET_TIMEOUT\""));
        assertTrue(report.contains("\"route_completion\": \"NONE\""));
        assertTrue(report.contains("\"any_route_lifecycle_observed\": false"));
        assertFalse(report.contains("uuid"));
        assertFalse(report.contains("session"));
        assertFalse(report.contains("hash"));
        assertFalse(report.contains("key"));
        assertFalse(report.contains("path"));
        assertFalse(report.contains("raw"));
        assertFalse(report.contains("log"));
        assertFalse(report.contains("private"));
        assertFalse(report.contains("frame"));
    }

    @Test
    void enforcedLimitRequiresDeferredServerConnectedFlushAndTerminalSuccess() {
        var passed = outcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT,
                true, true, false, MinecraftProxyPlayerProbeTest.RouteCompletion.SUCCESS,
                false, true, false);
        assertTrue(passed.passed());

        assertFalse(outcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT,
                false, true, false, MinecraftProxyPlayerProbeTest.RouteCompletion.SUCCESS,
                false, true, false).passed(),
                "a direct route is not the required Bungee early-route fixture path");
        assertFalse(outcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT,
                true, true, false, MinecraftProxyPlayerProbeTest.RouteCompletion.NONE,
                false, true, false).passed(),
                "DEFERRED/DISPATCHED cannot stand in for the connect callback completion");
    }

    @Test
    void enforcedQuarantineRequiresOnlyQuarantineAdmission() {
        assertTrue(outcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_QUARANTINE,
                true, true, false, MinecraftProxyPlayerProbeTest.RouteCompletion.SUCCESS,
                false, false, true).passed());
        assertFalse(outcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_QUARANTINE,
                true, true, false, MinecraftProxyPlayerProbeTest.RouteCompletion.SUCCESS,
                false, true, true).passed());
    }

    @Test
    void syntheticPolicyPathUsesThePublisherPathForEachProxy() {
        Path data = Path.of("fixture-data");
        Path velocity = MinecraftProxyPlayerProbeTest.ProbeHarness
                .syntheticDispositionConfigurationPath(
                        data, MinecraftProxyPlayerProbeTest.ProxyKind.VELOCITY);
        Path bungee = MinecraftProxyPlayerProbeTest.ProbeHarness
                .syntheticDispositionConfigurationPath(
                        data, MinecraftProxyPlayerProbeTest.ProxyKind.BUNGEE);

        assertEquals(data.resolve("policy/disposition-policy.textproto"), velocity);
        assertEquals(data.resolve("disposition-policy.textproto"), bungee);
        assertFalse(bungee.startsWith(data.resolve("policy")),
                "Bungee must not write an unused policy child directory");
    }

    @Test
    void bungeeCompletionRequiresThisDeferredActionAndTerminalSuccess() {
        String limitSuccess = "MCAce disposition route completion=SUCCESS player=test"
                + " action=LIMIT source=deferred-disposition session-bound=true";
        assertEquals(MinecraftProxyPlayerProbeTest.RouteCompletion.SUCCESS,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeDispositionRouteCompletion(
                        limitSuccess, MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT));

        assertEquals(MinecraftProxyPlayerProbeTest.RouteCompletion.FAILED,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeDispositionRouteCompletion(
                        limitSuccess.replace("SUCCESS", "FAILED"),
                        MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT));
        assertEquals(MinecraftProxyPlayerProbeTest.RouteCompletion.NONE,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeDispositionRouteCompletion(
                        limitSuccess.replace("source=deferred-disposition", "source=direct"),
                        MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT));
        assertEquals(MinecraftProxyPlayerProbeTest.RouteCompletion.NONE,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeDispositionRouteCompletion(
                        limitSuccess.replace("action=LIMIT", "action=QUARANTINE"),
                        MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT));
        assertEquals(MinecraftProxyPlayerProbeTest.RouteCompletion.NONE,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeDispositionRouteCompletion(
                        limitSuccess.replace("session-bound=true", "session-bound=false"),
                        MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT));
    }

    @Test
    void bungeePublisherRequiresMatchingFreshPositiveSequenceAndActiveTransition() {
        String before = "MCAce: disposition catalog publish version=old active-sequence=1\n"
                + "MCAce: disposition status=ACTIVE sequence=1\n";
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(before, before));

        String after = before
                + "MCAce: disposition catalog publish version=current active-sequence=2\n"
                + "MCAce: disposition status=ACTIVE sequence=2\n";
        assertTrue(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(before, after));
        assertTrue(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(before,
                        before + "Aug 09 12:00:00 INFO: MCAce: disposition catalog publish version=current active-sequence=2\n"
                                + "Aug 09 12:00:00 INFO: MCAce: disposition status=ACTIVE sequence=2\n"),
                "ordinary bounded logger prefixes remain accepted");
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(before,
                        before + "untrusted chat MCAce: disposition catalog publish version=current active-sequence=2\n"
                                + "MCAce: disposition status=ACTIVE sequence=2\n"),
                "an embedded marker outside a controlled logger boundary is not publisher evidence");

        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(before,
                        before + "MCAce: disposition catalog publish version=current active-sequence=2\n"
                                + "MCAce: disposition status=ACTIVE sequence=1\n"),
                "a delayed old ACTIVE marker cannot prove the new publish is active");
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(
                        before.replace("active-sequence=1", "active-sequence=2")
                                .replace("sequence=1", "sequence=2"),
                        "MCAce: disposition catalog publish version=old active-sequence=2\n"
                                + "MCAce: disposition status=ACTIVE sequence=2\n"
                                + "MCAce: disposition catalog publish version=current active-sequence=2\n"
                                + "MCAce: disposition status=ACTIVE sequence=2\n"),
                "a sequence must strictly advance beyond the observed baseline");
        String acknowledgementAheadOfActiveBaseline =
                "MCAce: disposition catalog publish version=old active-sequence=2\n"
                        + "MCAce: disposition status=ACTIVE sequence=1\n";
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(acknowledgementAheadOfActiveBaseline,
                        acknowledgementAheadOfActiveBaseline
                                + "MCAce: disposition catalog publish version=current active-sequence=2\n"
                                + "MCAce: disposition status=ACTIVE sequence=2\n"),
                "the baseline lower bound includes both prior acknowledgements and ACTIVE markers");
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(before,
                        before + "MCAce: disposition catalog publish version=current active-sequence=2\n"
                                + "MCAce: disposition catalog publish version=current active-sequence=2\n"
                                + "MCAce: disposition status=ACTIVE sequence=2\n"),
                "duplicate suffix publish acknowledgements are ambiguous and fail closed");
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(before,
                        before + "MCAce: disposition catalog publish version=current active-sequence=2\n"
                                + "MCAce: disposition status=ACTIVE sequence=2\n"
                                + "MCAce: disposition status=ACTIVE sequence=2\n"),
                "duplicate suffix ACTIVE markers are ambiguous and fail closed");
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(before,
                        before + "MCAce: disposition catalog publish version=current active-sequence=none\n"
                                + "MCAce: disposition status=ACTIVE sequence=2\n"));
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .bungeeFreshPublisherActivationObserved(before,
                        before + "MCAce: disposition catalog publish failed; active policy unchanged"
                                + " active-sequence=2\nMCAce: disposition status=ACTIVE sequence=2\n"));
        for (String invalid : java.util.List.of(
                "MCAce: disposition catalog publish version=current active-sequence=none\n"
                        + "MCAce: disposition status=ACTIVE sequence=2\n",
                "MCAce: disposition catalog publish version=current active-sequence=two\n"
                        + "MCAce: disposition status=ACTIVE sequence=2\n",
                "MCAce: disposition catalog publish version=current active-sequence=0\n"
                        + "MCAce: disposition status=ACTIVE sequence=2\n",
                "MCAce: disposition catalog publish version=current active-sequence=9223372036854775808\n"
                        + "MCAce: disposition status=ACTIVE sequence=2\n",
                "MCAce: disposition catalog publish version=current active-sequence=2\n"
                        + "MCAce: disposition status=ACTIVE sequence=none\n",
                "MCAce: disposition status=ACTIVE sequence=2\n")) {
            assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                    .bungeeFreshPublisherActivationObserved(before, before + invalid), invalid);
        }
    }

    @Test
    void monitorRejectsEveryControlledBungeeRouteLifecycleSource() {
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeAnyRouteLifecycleObserved(
                "MCAce manifest disposition: action=LIMIT result=NOT_ENFORCED\n"));
        assertTrue(MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeAnyRouteLifecycleObserved(
                "MCAce disposition route completion=SUCCESS player=test action=LIMIT source=direct session-bound=true\n"),
                "the raw product marker is a controlled no-prefix form");
        assertTrue(MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeAnyRouteLifecycleObserved(
                "Aug 09 12:00:00 INFO: MCAce disposition route completion=SUCCESS player=test action=LIMIT source=direct session-bound=true\n"),
                "the ordinary Bungee logger prefix remains a controlled route marker");
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeAnyRouteLifecycleObserved(
                "untrusted chat MCAce disposition route completion=SUCCESS player=test action=LIMIT source=direct session-bound=true\n"),
                "an embedded route marker outside the logger boundary is not evidence");
        for (String lifecycle : java.util.List.of(
                "MCAce disposition route completion=SUCCESS player=test action=LIMIT source=direct session-bound=true\n",
                "MCAce disposition route completion=SUCCESS player=test action=LIMIT source=heartbeat session-bound=true\n",
                "MCAce deferred disposition route result=DISPATCHED player=test action=LIMIT source=HEARTBEAT session-bound=true\n",
                "MCAce deferred disposition route result=DISPATCHED player=test action=LIMIT source=OTHER session-bound=true\n",
                "MCAce deferred disposition route retry: action=LIMIT result=LIMITED_DEFERRED\n",
                "MCAce heartbeat missing temporary route result=DISPATCHED\n",
                "MCAce manifest disposition route result=SUCCESS\n")) {
            assertTrue(MinecraftProxyPlayerProbeTest.ProbeHarness.bungeeAnyRouteLifecycleObserved(lifecycle), lifecycle);
        }
        var contaminated = outcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.MONITOR_LIMIT,
                false, false, true, MinecraftProxyPlayerProbeTest.RouteCompletion.NONE,
                true, false, false);
        assertFalse(contaminated.passed(), "MONITOR must be inert even when the route is not the expected source");
    }

    @Test
    void configurationAuthenticationRequiresAllRawPeerMilestonesBeforePlay() {
        assertTrue(evidence(
                MinecraftProxyPlayerProbeTest.ServerHelloStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthOutboundStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthResultStage.ACCEPTED_CONFIGURATION, true)
                .acceptedDuringConfiguration());
        assertFalse(evidence(
                MinecraftProxyPlayerProbeTest.ServerHelloStage.PLAY,
                MinecraftProxyPlayerProbeTest.AuthOutboundStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthResultStage.ACCEPTED_CONFIGURATION, true)
                .acceptedDuringConfiguration(), "ServerHello observed in PLAY is not configuration authentication");
        assertFalse(evidence(
                MinecraftProxyPlayerProbeTest.ServerHelloStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthOutboundStage.PLAY,
                MinecraftProxyPlayerProbeTest.AuthResultStage.ACCEPTED_CONFIGURATION, true)
                .acceptedDuringConfiguration(), "authentication frames sent in PLAY are not configuration authentication");
        assertFalse(evidence(
                MinecraftProxyPlayerProbeTest.ServerHelloStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthOutboundStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthResultStage.ACCEPTED_PLAY, true)
                .acceptedDuringConfiguration(), "accepted AuthResult observed in PLAY is not configuration authentication");
    }

    @Test
    void publisherUsesPerSourceCursorsAndOnlyAcceptsExactMirrors() {
        String old = "MCAce: disposition catalog publish version=old active-sequence=1\n"
                + "MCAce: disposition status=ACTIVE sequence=1\n";
        String current = "MCAce: disposition catalog publish version=current active-sequence=2\n"
                + "MCAce: disposition status=ACTIVE sequence=2\n";
        var before = snapshot(java.util.Map.of(
                "stdout", source("stdout-v1", old), "proxy", source("proxy-v1", "")));
        assertEquals(MinecraftProxyPlayerProbeTest.PublisherGate.ACTIVE,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeePublisherGate(before,
                        snapshot(java.util.Map.of("stdout", source("stdout-v1", old + current),
                                "proxy", source("proxy-v1", "")))));
        assertEquals(MinecraftProxyPlayerProbeTest.PublisherGate.MIRRORED_MATCH,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeePublisherGate(before,
                        snapshot(java.util.Map.of("stdout", source("stdout-v1", old + current),
                                "proxy", source("proxy-v1", current)))));
        assertEquals(MinecraftProxyPlayerProbeTest.PublisherGate.CROSS_SOURCE_CONFLICT,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeePublisherGate(before,
                        snapshot(java.util.Map.of("stdout", source("stdout-v1", old + current),
                                "proxy", source("proxy-v1", current.replace("=2", "=3"))))));
        assertEquals(MinecraftProxyPlayerProbeTest.PublisherGate.SOURCE_DUPLICATE_ACK,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeePublisherGate(before,
                        snapshot(java.util.Map.of("stdout", source("stdout-v1", old + current + current),
                                "proxy", source("proxy-v1", "")))));
        assertEquals(MinecraftProxyPlayerProbeTest.PublisherGate.SOURCE_IDENTITY_CHANGED,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeePublisherGate(before,
                        snapshot(java.util.Map.of("stdout", source("stdout-v2", old + current),
                                "proxy", source("proxy-v1", "")))));
        assertEquals(MinecraftProxyPlayerProbeTest.PublisherGate.SOURCE_TRUNCATED,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeePublisherGate(before,
                        snapshot(java.util.Map.of("stdout", source("stdout-v1", "rewritten"),
                                "proxy", source("proxy-v1", "")))));
        assertEquals(MinecraftProxyPlayerProbeTest.PublisherGate.SOURCE_SET_CHANGED,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeePublisherGate(before,
                        snapshot(java.util.Map.of("stdout", source("stdout-v1", old + current)))));
        String acknowledgedFour = "MCAce: disposition catalog publish version=old active-sequence=4\n"
                + "MCAce: disposition status=ACTIVE sequence=1\n";
        var multiSourceBaseline = snapshot(java.util.Map.of(
                "stdout", source("stdout-v1", old), "proxy", source("proxy-v1", acknowledgedFour)));
        assertEquals(MinecraftProxyPlayerProbeTest.PublisherGate.NOT_FRESH,
                MinecraftProxyPlayerProbeTest.ProbeHarness.bungeePublisherGate(multiSourceBaseline,
                        snapshot(java.util.Map.of("stdout", source("stdout-v1", old + current.replace("=2", "=4")),
                                "proxy", source("proxy-v1", acknowledgedFour)))),
                "baseline freshness is the union over every stable source, not only ACTIVE markers");
    }

    @Test
    void authenticationAndRemoteLivenessRemainOrthogonal() {
        var acceptedInPlay = evidence(
                MinecraftProxyPlayerProbeTest.ServerHelloStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthOutboundStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthResultStage.ACCEPTED_PLAY, true);
        assertTrue(acceptedInPlay.authenticationAcceptedAnyPhase());
        assertFalse(acceptedInPlay.acceptedDuringConfiguration());
        assertTrue(MinecraftProxyPlayerProbeTest.RemoteLiveness.QUIET_TIMEOUT.openOutcome());
        assertFalse(MinecraftProxyPlayerProbeTest.RemoteLiveness.EOF_OR_RESET.openOutcome());
    }

    private static MinecraftProxyPlayerProbeTest.BungeeDispositionCaseOutcome outcome(
            MinecraftProxyPlayerProbeTest.DispositionScenario scenario,
            boolean deferred, boolean dispatched,
            boolean anyRouteLifecycle,
            MinecraftProxyPlayerProbeTest.RouteCompletion completion,
            boolean lobby, boolean limited, boolean quarantine) {
        return new MinecraftProxyPlayerProbeTest.BungeeDispositionCaseOutcome(
                scenario, true, true, MinecraftProxyPlayerProbeTest.PublisherGate.ACTIVE,
                true, true, true,
                MinecraftProxyPlayerProbeTest.ServerHelloStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthOutboundStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthResultStage.ACCEPTED_CONFIGURATION,
                true, deferred, dispatched, anyRouteLifecycle, lobby, limited, quarantine,
                completion, MinecraftProxyPlayerProbeTest.RemoteLiveness.QUIET_TIMEOUT,
                true, true, true);
    }

    private static MinecraftProxyPlayerProbeTest.AuthenticationEvidence evidence(
            MinecraftProxyPlayerProbeTest.ServerHelloStage hello,
            MinecraftProxyPlayerProbeTest.AuthOutboundStage outbound,
            MinecraftProxyPlayerProbeTest.AuthResultStage result,
            boolean acceptedAnyPhase) {
        return new MinecraftProxyPlayerProbeTest.AuthenticationEvidence(
                hello, outbound, result, acceptedAnyPhase);
    }

    private static MinecraftProxyPlayerProbeTest.ProbeHarness.PublisherSnapshot snapshot(
            java.util.Map<String, MinecraftProxyPlayerProbeTest.ProbeHarness.PublisherSourceCursor> sources) {
        return new MinecraftProxyPlayerProbeTest.ProbeHarness.PublisherSnapshot(true, sources);
    }

    private static MinecraftProxyPlayerProbeTest.ProbeHarness.PublisherSourceCursor source(
            String identity, String content) {
        return new MinecraftProxyPlayerProbeTest.ProbeHarness.PublisherSourceCursor(
                identity, content.getBytes(java.nio.charset.StandardCharsets.UTF_8).length, content);
    }
}
