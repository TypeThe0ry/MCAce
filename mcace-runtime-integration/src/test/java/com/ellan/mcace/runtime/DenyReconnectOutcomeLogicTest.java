package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/** Pure report-boundary logic; never starts a proxy, Paper, or network connection. */
final class DenyReconnectOutcomeLogicTest {
    @Test
    void verifiedCleanReconnectPassesWithoutClaimingPersistentBanState() {
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome outcome = outcome(
                MinecraftProxyPlayerProbeTest.DisconnectEvidence.PROTOCOL_DISCONNECT,
                false, false, true, true, true, true);

        assertTrue(outcome.firstConnectionClosed());
        assertTrue(outcome.passed());
        assertTrue("VERIFIED_LOBBY".equals(outcome.reconnectOutcome()));
    }

    @Test
    void denyNeedsAConnectionLocalCloseSignal() {
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome outcome = outcome(
                MinecraftProxyPlayerProbeTest.DisconnectEvidence.NONE,
                false, false, true, true, true, true);

        assertFalse(outcome.firstConnectionClosed());
        assertFalse(outcome.passed());
    }

    @Test
    void cleanReconnectRejectsRestrictedBackendOrMissingNewLobbyAdmission() {
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome restricted = outcome(
                MinecraftProxyPlayerProbeTest.DisconnectEvidence.REMOTE_EOF_OR_RESET,
                true, false, true, true, true, true);
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome noNewLobby = outcome(
                MinecraftProxyPlayerProbeTest.DisconnectEvidence.REMOTE_EOF_OR_RESET,
                false, false, true, true, true, false);

        assertFalse(restricted.passed());
        assertFalse(noNewLobby.passed());
        assertTrue("NOT_VERIFIED".equals(noNewLobby.reconnectOutcome()));
    }

    @Test
    void sameOfflineIdentityStillRequiresAnIndependentAuthenticatedSession() {
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome reusedSession = outcome(
                MinecraftProxyPlayerProbeTest.DisconnectEvidence.PROTOCOL_DISCONNECT,
                false, false, false, true, true, true);

        assertFalse(reusedSession.passed());
    }

    @Test
    void fixedReconnectStagesAndTerminationFailClosed() {
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome preAuth = outcome(
                MinecraftProxyPlayerProbeTest.DisconnectEvidence.PROTOCOL_DISCONNECT,
                false, false, true, true, true, true,
                MinecraftProxyPlayerProbeTest.CleanReconnectStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.CleanReconnectTermination.READ_TIMEOUT,
                MinecraftProxyPlayerProbeTest.OldSessionCleanup.RECONNECT_FIXTURE_READY,
                true);
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome cleanupTimeout = outcome(
                MinecraftProxyPlayerProbeTest.DisconnectEvidence.PROTOCOL_DISCONNECT,
                false, false, true, true, true, true,
                MinecraftProxyPlayerProbeTest.CleanReconnectStage.NOT_STARTED,
                MinecraftProxyPlayerProbeTest.CleanReconnectTermination.NONE,
                MinecraftProxyPlayerProbeTest.OldSessionCleanup.TIMEOUT,
                true);

        assertFalse(preAuth.passed());
        assertFalse(cleanupTimeout.passed());
    }

    @Test
    void admissionBaselineReturnsOnlyAfterTheFullStableWindow() throws Exception {
        AtomicLong now = new AtomicLong();
        AtomicInteger samples = new AtomicInteger();

        int stable = MinecraftProxyPlayerProbeTest.waitForStableCount(
                () -> samples.getAndIncrement() == 0 ? 0 : 1,
                () -> true,
                500,
                1_000,
                now::get,
                millis -> now.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis)));

        assertEquals(1, stable);
        assertTrue(now.get() >= TimeUnit.MILLISECONDS.toNanos(550));
    }

    @Test
    void changingCountAtDeadlineFailsClosed() {
        AtomicLong now = new AtomicLong();
        AtomicInteger samples = new AtomicInteger();

        assertThrows(IOException.class, () -> MinecraftProxyPlayerProbeTest.waitForStableCount(
                samples::getAndIncrement,
                () -> true,
                100,
                250,
                now::get,
                millis -> now.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis))));
    }

    @Test
    void stoppedPaperFailsTheStabilityGate() {
        AtomicLong now = new AtomicLong();

        assertThrows(IOException.class, () -> MinecraftProxyPlayerProbeTest.waitForStableCount(
                () -> 0,
                () -> now.get() < TimeUnit.MILLISECONDS.toNanos(150),
                500,
                1_000,
                now::get,
                millis -> now.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis))));
    }

    @Test
    void cleanupGateRequiresCurrentGenerationRegistryProductAndLastListenerMarkers() throws Exception {
        AtomicLong now = new AtomicLong();
        AtomicInteger registryChecks = new AtomicInteger();
        AtomicBoolean registryEmpty = new AtomicBoolean();
        AtomicBoolean productReady = new AtomicBoolean();

        MinecraftProxyPlayerProbeTest.OldSessionCleanup cleanup =
                MinecraftProxyPlayerProbeTest.waitForOldSessionCleanupGate(
                        () -> true,
                        () -> true,
                        () -> {
                            boolean empty = registryChecks.incrementAndGet() >= 2;
                            registryEmpty.set(empty);
                            return empty;
                        },
                        () -> {
                            assertTrue(registryEmpty.get());
                            productReady.set(true);
                            return true;
                        },
                        () -> {
                            assertTrue(registryEmpty.get());
                            assertTrue(productReady.get());
                            return true;
                        },
                        500,
                        now::get,
                        millis -> now.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis)));

        assertEquals(MinecraftProxyPlayerProbeTest.OldSessionCleanup.RECONNECT_FIXTURE_READY,
                cleanup);
        assertTrue(MinecraftProxyPlayerProbeTest.mayOpenCleanReconnect(cleanup));
    }

    @Test
    void absentProductOrLastListenerMarkerKeepsSecondSocketClosed() throws Exception {
        AtomicLong registryTimeoutClock = new AtomicLong();
        MinecraftProxyPlayerProbeTest.OldSessionCleanup registryTimeout =
                MinecraftProxyPlayerProbeTest.waitForOldSessionCleanupGate(
                        () -> true, () -> true, () -> false, () -> true, () -> true,
                        150, registryTimeoutClock::get,
                        millis -> registryTimeoutClock.addAndGet(
                                TimeUnit.MILLISECONDS.toNanos(millis)));

        AtomicLong markerTimeoutClock = new AtomicLong();
        MinecraftProxyPlayerProbeTest.OldSessionCleanup markerTimeout =
                MinecraftProxyPlayerProbeTest.waitForOldSessionCleanupGate(
                        () -> true, () -> true, () -> true, () -> false, () -> true,
                        150, markerTimeoutClock::get,
                        millis -> markerTimeoutClock.addAndGet(
                                TimeUnit.MILLISECONDS.toNanos(millis)));

        AtomicLong listenerTimeoutClock = new AtomicLong();
        MinecraftProxyPlayerProbeTest.OldSessionCleanup listenerTimeout =
                MinecraftProxyPlayerProbeTest.waitForOldSessionCleanupGate(
                        () -> true, () -> true, () -> true, () -> true, () -> false,
                        150, listenerTimeoutClock::get,
                        millis -> listenerTimeoutClock.addAndGet(
                                TimeUnit.MILLISECONDS.toNanos(millis)));

        assertEquals(MinecraftProxyPlayerProbeTest.OldSessionCleanup.TIMEOUT,
                registryTimeout);
        assertEquals(MinecraftProxyPlayerProbeTest.OldSessionCleanup.DISCONNECT_LAST_LISTENER_OBSERVED,
                markerTimeout);
        assertEquals(MinecraftProxyPlayerProbeTest.OldSessionCleanup.TIMEOUT, listenerTimeout);
        for (MinecraftProxyPlayerProbeTest.OldSessionCleanup cleanup
                : EnumSet.complementOf(EnumSet.of(
                        MinecraftProxyPlayerProbeTest.OldSessionCleanup
                                .RECONNECT_FIXTURE_READY))) {
            assertFalse(MinecraftProxyPlayerProbeTest.mayOpenCleanReconnect(cleanup));
        }
        assertEquals(MinecraftProxyPlayerProbeTest.OldSessionCleanup.OBSERVER_UNAVAILABLE,
                MinecraftProxyPlayerProbeTest.waitForOldSessionCleanupGate(
                        () -> true, () -> false, () -> true, () -> true, () -> true,
                        150, () -> 0L, millis -> { }));
    }

    @Test
    void markerOrderDoesNotPermitReconnectUntilBothPostBaselineMarkersAdvance() throws Exception {
        AtomicLong now = new AtomicLong();
        AtomicInteger step = new AtomicInteger();

        MinecraftProxyPlayerProbeTest.OldSessionCleanup cleanup =
                MinecraftProxyPlayerProbeTest.waitForOldSessionCleanupGate(
                        () -> true,
                        () -> true,
                        () -> step.get() >= 1,
                        () -> step.get() >= 3,
                        () -> step.get() >= 2,
                        500,
                        now::get,
                        millis -> {
                            now.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis));
                            step.incrementAndGet();
                        });

        assertEquals(MinecraftProxyPlayerProbeTest.OldSessionCleanup.RECONNECT_FIXTURE_READY,
                cleanup);
        assertTrue(MinecraftProxyPlayerProbeTest.mayOpenCleanReconnect(cleanup));
    }

    @Test
    void generationOrObserverAbsenceFailsClosedWithoutRetryingASecondPeer() throws Exception {
        AtomicLong now = new AtomicLong();
        AtomicInteger aliveChecks = new AtomicInteger();

        MinecraftProxyPlayerProbeTest.OldSessionCleanup generationChanged =
                MinecraftProxyPlayerProbeTest.waitForOldSessionCleanupGate(
                        () -> aliveChecks.incrementAndGet() < 3,
                        () -> true,
                        () -> true,
                        () -> true,
                        () -> true,
                        500,
                        now::get,
                        millis -> now.addAndGet(TimeUnit.MILLISECONDS.toNanos(millis)));

        assertEquals(MinecraftProxyPlayerProbeTest.OldSessionCleanup.OBSERVER_UNAVAILABLE,
                generationChanged);
        assertFalse(MinecraftProxyPlayerProbeTest.mayOpenCleanReconnect(generationChanged));
    }

    @Test
    void controlledStatusParserUsesOnlyPlayersOnline() throws Exception {
        assertTrue(MinecraftProxyPlayerProbeTest.controlledStatusRegistryEmpty(
                "{\"players\":{\"max\":20,\"online\":0},\"description\":{}}"));
        assertTrue(MinecraftProxyPlayerProbeTest.controlledStatusRegistryEmpty(
                "{\"players\":{\"sample\":[{\"name\":\"}\"}],\"online\":0,\"max\":20}}"));
        assertFalse(MinecraftProxyPlayerProbeTest.controlledStatusRegistryEmpty(
                "{\"players\":{\"max\":20,\"online\":1},\"description\":{}}"));
        assertThrows(IOException.class,
                () -> MinecraftProxyPlayerProbeTest.controlledStatusRegistryEmpty(
                        "{\"description\":{\"online\":0}}"));
    }

    @Test
    void reportContainsOnlyFixedReconnectClassifications() {
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome outcome = outcome(
                MinecraftProxyPlayerProbeTest.DisconnectEvidence.PROTOCOL_DISCONNECT,
                false, false, true, true, true, true);

        String report = RealProxyDispositionMatrixGateTest
                .phaseTwoVelocityDenyReconnectJson(outcome);

        assertTrue(report.contains("\"clean_reconnect_stage\": \"LOBBY_VERIFIED\""));
        assertTrue(report.contains("\"fixture_login_ratelimit_disabled\": true"));
        assertTrue(report.contains("\"termination\": \"NONE\""));
        assertTrue(report.contains(
                "\"old_session_cleanup\": \"RECONNECT_FIXTURE_READY\""));
        assertTrue(report.contains("\"reconnect_fixture_ready\": true"));
        assertFalse(report.contains("session_id"));
        assertFalse(report.contains("uuid"));
        assertFalse(report.contains("sha256"));
        assertFalse(report.contains("policy_bytes"));
        assertFalse(report.contains("disconnect_reason"));
        assertFalse(report.contains("raw_frame"));
        assertFalse(report.contains("C:\\"));
    }

    @Test
    void fixtureLoginRatelimitMustBeExplicitlyDisabledAndReported() throws Exception {
        String configured = MinecraftProxyPlayerProbeTest
                .disableVelocityFixtureLoginRatelimit("login-ratelimit = 3000\n");
        assertEquals("login-ratelimit = 0\n", configured);
        assertThrows(IOException.class, () -> MinecraftProxyPlayerProbeTest
                .disableVelocityFixtureLoginRatelimit("login-ratelimit = 0\n"));
        assertThrows(IOException.class, () -> MinecraftProxyPlayerProbeTest
                .disableVelocityFixtureLoginRatelimit(
                        "login-ratelimit = 3000\nlogin-ratelimit = 3000\n"));

        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome unsafe = outcome(
                MinecraftProxyPlayerProbeTest.DisconnectEvidence.PROTOCOL_DISCONNECT,
                false, false, true, true, true, true,
                MinecraftProxyPlayerProbeTest.CleanReconnectStage.LOBBY_VERIFIED,
                MinecraftProxyPlayerProbeTest.CleanReconnectTermination.NONE,
                MinecraftProxyPlayerProbeTest.OldSessionCleanup.RECONNECT_FIXTURE_READY,
                false);
        assertFalse(unsafe.passed());
        assertTrue(RealProxyDispositionMatrixGateTest
                .phaseTwoVelocityDenyReconnectJson(unsafe)
                .contains("\"fixture_login_ratelimit_disabled\": false"));
    }

    private static MinecraftProxyPlayerProbeTest.DenyReconnectOutcome outcome(
            MinecraftProxyPlayerProbeTest.DisconnectEvidence disconnectEvidence,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            boolean independentAuthenticatedSession,
            boolean reconnectAuthenticationAccepted,
            boolean reconnectConfigurationCompleted,
            boolean reconnectLobbyVerifiedAdmission) {
        return outcome(disconnectEvidence, limitedAdmission, quarantineAdmission,
                independentAuthenticatedSession, reconnectAuthenticationAccepted,
                reconnectConfigurationCompleted, reconnectLobbyVerifiedAdmission,
                MinecraftProxyPlayerProbeTest.CleanReconnectStage.LOBBY_VERIFIED,
                MinecraftProxyPlayerProbeTest.CleanReconnectTermination.NONE,
                MinecraftProxyPlayerProbeTest.OldSessionCleanup.RECONNECT_FIXTURE_READY,
                true);
    }

    private static MinecraftProxyPlayerProbeTest.DenyReconnectOutcome outcome(
            MinecraftProxyPlayerProbeTest.DisconnectEvidence disconnectEvidence,
            boolean limitedAdmission,
            boolean quarantineAdmission,
            boolean independentAuthenticatedSession,
            boolean reconnectAuthenticationAccepted,
            boolean reconnectConfigurationCompleted,
            boolean reconnectLobbyVerifiedAdmission,
            MinecraftProxyPlayerProbeTest.CleanReconnectStage cleanReconnectStage,
            MinecraftProxyPlayerProbeTest.CleanReconnectTermination cleanReconnectTermination,
            MinecraftProxyPlayerProbeTest.OldSessionCleanup oldSessionCleanup,
            boolean fixtureLoginRatelimitDisabled) {
        return new MinecraftProxyPlayerProbeTest.DenyReconnectOutcome(
                true, fixtureLoginRatelimitDisabled, true, true, true, true,
                disconnectEvidence,
                limitedAdmission, quarantineAdmission, true,
                independentAuthenticatedSession, true,
                reconnectAuthenticationAccepted, reconnectConfigurationCompleted,
                reconnectLobbyVerifiedAdmission,
                cleanReconnectStage, cleanReconnectTermination, oldSessionCleanup,
                true, true);
    }
}
