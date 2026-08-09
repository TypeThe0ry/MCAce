package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Default-skipped, content-free report boundary for real proxy disposition process cases. */
final class RealProxyDispositionMatrixGateTest {
    private static final String OPT_IN = "mcace.runtime.disposition.enabled";

    @Test
    @Timeout(360)
    void velocityMonitorLimitSyntheticExactManifestIsInert() throws Exception {
        runVelocity(MinecraftProxyPlayerProbeTest.DispositionScenario.MONITOR_LIMIT);
    }

    @Test
    @Timeout(360)
    void velocityEnforceLimitSyntheticExactManifestRoutesOnlyToLimited() throws Exception {
        runVelocity(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT);
    }

    @Test
    @Timeout(360)
    void velocityEnforceQuarantineSyntheticExactManifestRoutesOnlyToQuarantine() throws Exception {
        runVelocity(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_QUARANTINE);
    }

    @Test
    @Timeout(360)
    void bungeeMonitorLimitSyntheticExactManifestIsInert() throws Exception {
        runBungee(MinecraftProxyPlayerProbeTest.DispositionScenario.MONITOR_LIMIT);
    }

    @Test
    @Timeout(360)
    void bungeeEnforceLimitSyntheticExactManifestRoutesOnlyToLimited() throws Exception {
        runBungee(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT);
    }

    @Test
    @Timeout(360)
    void bungeeEnforceQuarantineSyntheticExactManifestRoutesOnlyToQuarantine() throws Exception {
        runBungee(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_QUARANTINE);
    }

    @Test
    @Timeout(420)
    void velocityEnforceDenyClosesCurrentConnectionAndAllowsCleanReconnect() throws Exception {
        optIn();
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome outcome =
                MinecraftProxyPlayerProbeTest.runVelocityDenyReconnectCase();
        Path reportRoot = reportRoot(repositoryRoot(), "velocity-enforce_deny_reconnect");
        String report = phaseTwoVelocityDenyReconnectJson(outcome);
        Files.writeString(reportRoot.resolve("report.json"), report, StandardCharsets.UTF_8);
        assertTrue(onlySanitizedReport(reportRoot), "matrix run retained non-report material");
        assertTrue(outcome.passed(), report);
    }

    /** Bungee remains an honest Phase-1 real transport baseline until its Phase-2 driver lands. */
    @Test
    @Timeout(240)
    void bungeeRealDispositionMatrixPhaseOneGate() throws Exception {
        optIn();
        Path repository = repositoryRoot();
        Path legacyRuns = repository.resolve("build/runtime-player-probe/runs");
        Set<Path> before = children(legacyRuns);
        Path reportRoot = reportRoot(repository, "bungee-phase-one");
        boolean baseline = false;
        boolean cleanupZero = false;
        PrintStream originalOut = System.out;
        try {
            System.setOut(new PrintStream(OutputStream.nullOutputStream(), true, StandardCharsets.UTF_8));
            new MinecraftProxyPlayerProbeTest()
                    .realBungeeIpForwardingOfflinePlayerProbeReachesMCAceChannel();
            baseline = true;
            cleanupZero = true;
        } finally {
            System.setOut(originalOut);
            deleteNewChildren(legacyRuns, before);
            String report = phaseOneBungeeJson(baseline, cleanupZero);
            Files.writeString(reportRoot.resolve("report.json"), report, StandardCharsets.UTF_8);
            assertTrue(onlySanitizedReport(reportRoot), "matrix run retained non-report material");
        }
        assertTrue(baseline && cleanupZero,
                "Bungee Phase-1 real transport prerequisite did not complete");
    }

    private static void runVelocity(MinecraftProxyPlayerProbeTest.DispositionScenario scenario)
            throws Exception {
        optIn();
        MinecraftProxyPlayerProbeTest.DispositionCaseOutcome outcome =
                MinecraftProxyPlayerProbeTest.runVelocityDispositionCase(scenario);
        Path reportRoot = reportRoot(repositoryRoot(), "velocity-" + scenario.name().toLowerCase());
        String report = phaseTwoVelocityJson(outcome);
        Files.writeString(reportRoot.resolve("report.json"), report, StandardCharsets.UTF_8);
        assertTrue(onlySanitizedReport(reportRoot), "matrix run retained non-report material");
        assertTrue(outcome.passed(), report);
    }

    /**
     * Bungee Phase-2 is intentionally independent from the former Phase-1 transport baseline.
     * Its enforced cases require the product's post-{@code ServerConnectedEvent} one-shot flush
     * and the Bungee connect callback's terminal completion marker.
     */
    private static void runBungee(MinecraftProxyPlayerProbeTest.DispositionScenario scenario)
            throws Exception {
        optIn();
        MinecraftProxyPlayerProbeTest.BungeeDispositionCaseOutcome outcome =
                MinecraftProxyPlayerProbeTest.runBungeeDispositionCase(scenario);
        Path reportRoot = reportRoot(repositoryRoot(), "bungee-" + scenario.name().toLowerCase());
        String report = phaseTwoBungeeJson(outcome);
        Files.writeString(reportRoot.resolve("report.json"), report, StandardCharsets.UTF_8);
        assertTrue(onlySanitizedReport(reportRoot), "matrix run retained non-report material");
        assertTrue(outcome.passed(), report);
    }

    private static void optIn() {
        Assumptions.assumeTrue(Boolean.getBoolean(OPT_IN),
                "real proxy disposition matrix is opt-in; set " + OPT_IN + "=true");
    }

    private static Path reportRoot(Path repository, String fixedPrefix) throws Exception {
        Path root = repository.resolve("build/runtime-disposition-matrix/runs")
                .resolve(fixedPrefix + "-" + Instant.now().toString()
                        .replace(':', '-').replace('.', '-'));
        Files.createDirectories(root);
        return root;
    }

    private static String phaseTwoVelocityJson(
            MinecraftProxyPlayerProbeTest.DispositionCaseOutcome outcome) {
        String expectedBackend = switch (outcome.scenario()) {
            case MONITOR_LIMIT -> "LOBBY";
            case ENFORCE_LIMIT -> "LIMITED";
            case ENFORCE_QUARANTINE -> "QUARANTINE";
        };
        return "{\n"
                + "  \"schema\": \"DISPOSITION_MATRIX_PHASE_TWO\",\n"
                + "  \"platform\": \"VELOCITY\",\n"
                + "  \"case\": \"" + outcome.scenario().name() + "\",\n"
                + "  \"expected_backend\": \"" + expectedBackend + "\",\n"
                + "  \"forwarding_configured\": " + outcome.forwardingConfigured() + ",\n"
                + "  \"administrator_publisher_active\": " + outcome.publisherActive() + ",\n"
                + "  \"synthetic_exact_manifest_sent\": " + outcome.syntheticManifestSent() + ",\n"
                + "  \"authentication_accepted\": " + outcome.authenticationAccepted() + ",\n"
                + "  \"expected_disposition_result_observed\": "
                + outcome.dispositionResultObserved() + ",\n"
                + "  \"lobby_admission\": " + outcome.lobbyAdmission() + ",\n"
                + "  \"limited_admission\": " + outcome.limitedAdmission() + ",\n"
                + "  \"quarantine_admission\": " + outcome.quarantineAdmission() + ",\n"
                + "  \"route_completion\": \"" + outcome.routeCompletion().name() + "\",\n"
                + "  \"current_connection_retained\": " + outcome.connectionRetained() + ",\n"
                + "  \"owned_process_cleanup_zero\": " + outcome.cleanupZero() + ",\n"
                + "  \"run_material_removed\": " + outcome.workMaterialRemoved() + ",\n"
                + "  \"monitor_warn\": \"NOT_EXECUTED\",\n"
                + "  \"monitor_quarantine\": \"NOT_EXECUTED\",\n"
                + "  \"monitor_deny\": \"NOT_EXECUTED\",\n"
                + "  \"enforce_deny_reconnect\": \"NOT_EXECUTED\",\n"
                + "  \"selector_rejection_cases\": \"NOT_EXECUTED\",\n"
                + "  \"paper_hostile_admission_injection\": \"NOT_EXECUTED\",\n"
                + "  \"fabric_gui_coverage\": false,\n"
                + "  \"case_passed\": " + outcome.passed() + ",\n"
                + "  \"matrix_completed\": false\n"
                + "}\n";
    }

    static String phaseTwoVelocityDenyReconnectJson(
            MinecraftProxyPlayerProbeTest.DenyReconnectOutcome outcome) {
        return "{\n"
                + "  \"schema\": \"DISPOSITION_MATRIX_PHASE_TWO\",\n"
                + "  \"platform\": \"VELOCITY\",\n"
                + "  \"case\": \"ENFORCE_DENY_RECONNECT\",\n"
                + "  \"scope\": \"CURRENT_CONNECTION_THEN_CLEAN_RECONNECT\",\n"
                + "  \"forwarding_configured\": " + outcome.forwardingConfigured() + ",\n"
                + "  \"fixture_login_ratelimit_disabled\": "
                + outcome.fixtureLoginRatelimitDisabled() + ",\n"
                + "  \"administrator_publisher_active\": " + outcome.publisherActive() + ",\n"
                + "  \"first_synthetic_exact_manifest_sent\": "
                + outcome.firstSyntheticManifestSent() + ",\n"
                + "  \"first_authentication_accepted\": "
                + outcome.firstAuthenticationAccepted() + ",\n"
                + "  \"denied_result_observed\": " + outcome.deniedResultObserved() + ",\n"
                + "  \"first_connection_closed\": " + outcome.firstConnectionClosed() + ",\n"
                + "  \"disconnect_evidence\": \"" + outcome.disconnectEvidence().name() + "\",\n"
                + "  \"limited_admission\": " + outcome.limitedAdmission() + ",\n"
                + "  \"quarantine_admission\": " + outcome.quarantineAdmission() + ",\n"
                + "  \"same_offline_identity\": " + outcome.sameOfflineIdentity() + ",\n"
                + "  \"independent_authenticated_session\": "
                + outcome.independentAuthenticatedSession() + ",\n"
                + "  \"clean_manifest_sent\": " + outcome.cleanManifestSent() + ",\n"
                + "  \"clean_reconnect_authentication_accepted\": "
                + outcome.reconnectAuthenticationAccepted() + ",\n"
                + "  \"clean_reconnect_configuration_completed\": "
                + outcome.reconnectConfigurationCompleted() + ",\n"
                + "  \"clean_reconnect_lobby_verified_admission\": "
                + outcome.reconnectLobbyVerifiedAdmission() + ",\n"
                + "  \"clean_reconnect_stage\": \""
                + outcome.cleanReconnectStage().name() + "\",\n"
                + "  \"termination\": \""
                + outcome.cleanReconnectTermination().name() + "\",\n"
                + "  \"old_session_cleanup\": \""
                + outcome.oldSessionCleanup().name() + "\",\n"
                + "  \"reconnect_fixture_ready\": " + outcome.reconnectFixtureReady() + ",\n"
                + "  \"clean_reconnect_outcome\": \"" + outcome.reconnectOutcome() + "\",\n"
                + "  \"owned_process_cleanup_zero\": " + outcome.cleanupZero() + ",\n"
                + "  \"run_material_removed\": " + outcome.workMaterialRemoved() + ",\n"
                + "  \"fabric_gui_coverage\": false,\n"
                + "  \"case_passed\": " + outcome.passed() + ",\n"
                + "  \"matrix_completed\": false\n"
                + "}\n";
    }

    static String phaseTwoBungeeJson(
            MinecraftProxyPlayerProbeTest.BungeeDispositionCaseOutcome outcome) {
        String expectedBackend = switch (outcome.scenario()) {
            case MONITOR_LIMIT -> "LOBBY";
            case ENFORCE_LIMIT -> "LIMITED";
            case ENFORCE_QUARANTINE -> "QUARANTINE";
        };
        return "{\n"
                + "  \"schema\": \"DISPOSITION_MATRIX_PHASE_TWO\",\n"
                + "  \"platform\": \"BUNGEE\",\n"
                + "  \"case\": \"" + outcome.scenario().name() + "\",\n"
                + "  \"expected_backend\": \"" + expectedBackend + "\",\n"
                + "  \"forwarding_configured\": " + outcome.forwardingConfigured() + ",\n"
                + "  \"administrator_publisher_active\": " + outcome.publisherActive() + ",\n"
                + "  \"publisher_gate\": \"" + outcome.publisherGate().name() + "\",\n"
                + "  \"synthetic_exact_manifest_sent\": " + outcome.syntheticManifestSent() + ",\n"
                + "  \"authentication_accepted_during_configuration\": "
                + outcome.authenticationAccepted() + ",\n"
                + "  \"authentication_accepted_any_phase\": "
                + outcome.authenticationAcceptedAnyPhase() + ",\n"
                + "  \"server_hello_stage\": \"" + outcome.serverHelloStage().name() + "\",\n"
                + "  \"auth_outbound_stage\": \"" + outcome.authOutboundStage().name() + "\",\n"
                + "  \"auth_result_stage\": \"" + outcome.authResultStage().name() + "\",\n"
                + "  \"expected_disposition_result_observed\": "
                + outcome.dispositionResultObserved() + ",\n"
                + "  \"server_connected_deferred_route\": " + outcome.deferredRouteObserved() + ",\n"
                + "  \"server_connected_deferred_dispatch\": " + outcome.deferredRouteDispatched() + ",\n"
                + "  \"any_route_lifecycle_observed\": " + outcome.anyRouteLifecycleObserved() + ",\n"
                + "  \"lobby_admission\": " + outcome.lobbyAdmission() + ",\n"
                + "  \"limited_admission\": " + outcome.limitedAdmission() + ",\n"
                + "  \"quarantine_admission\": " + outcome.quarantineAdmission() + ",\n"
                + "  \"route_completion\": \"" + outcome.routeCompletion().name() + "\",\n"
                + "  \"remote_liveness\": \"" + outcome.remoteLiveness().name() + "\",\n"
                + "  \"current_connection_retained\": " + outcome.connectionRetained() + ",\n"
                + "  \"owned_process_cleanup_zero\": " + outcome.cleanupZero() + ",\n"
                + "  \"run_material_removed\": " + outcome.workMaterialRemoved() + ",\n"
                + "  \"monitor_warn\": \"NOT_EXECUTED\",\n"
                + "  \"monitor_quarantine\": \"NOT_EXECUTED\",\n"
                + "  \"monitor_deny\": \"NOT_EXECUTED\",\n"
                + "  \"enforce_deny_reconnect\": \"NOT_EXECUTED\",\n"
                + "  \"selector_rejection_cases\": \"NOT_EXECUTED\",\n"
                + "  \"paper_hostile_admission_injection\": \"NOT_EXECUTED\",\n"
                + "  \"fabric_gui_coverage\": false,\n"
                + "  \"case_passed\": " + outcome.passed() + ",\n"
                + "  \"matrix_completed\": false\n"
                + "}\n";
    }

    private static String phaseOneBungeeJson(boolean baseline, boolean cleanupZero) {
        return "{\n"
                + "  \"schema\": \"DISPOSITION_MATRIX_PHASE_ONE\",\n"
                + "  \"platform\": \"BUNGEE\",\n"
                + "  \"real_transport_baseline\": " + baseline + ",\n"
                + "  \"owned_process_cleanup_zero\": " + cleanupZero + ",\n"
                + "  \"phase_two_cases\": \"NOT_EXECUTED\",\n"
                + "  \"fabric_gui_coverage\": false,\n"
                + "  \"matrix_completed\": false\n"
                + "}\n";
    }

    private static Path repositoryRoot() throws Exception {
        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        while (current != null) {
            if (Files.isRegularFile(current.resolve("settings.gradle.kts"))) return current;
            current = current.getParent();
        }
        throw new IllegalStateException("MCAce repository root unavailable");
    }

    private static Set<Path> children(Path root) throws Exception {
        if (!Files.isDirectory(root)) return Set.of();
        try (var paths = Files.list(root)) {
            return Set.copyOf(paths.map(path -> path.toAbsolutePath().normalize()).toList());
        }
    }

    private static void deleteNewChildren(Path root, Set<Path> before) throws Exception {
        if (!Files.isDirectory(root)) return;
        Path normalizedRoot = root.toAbsolutePath().normalize();
        try (var paths = Files.list(normalizedRoot)) {
            for (Path candidate : paths.toList()) {
                Path normalized = candidate.toAbsolutePath().normalize();
                if (!before.contains(normalized) && normalized.getParent().equals(normalizedRoot)) {
                    deleteTree(normalized);
                }
            }
        }
    }

    private static void deleteTree(Path target) throws Exception {
        try (var paths = Files.walk(target)) {
            for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static boolean onlySanitizedReport(Path root) throws Exception {
        try (var paths = Files.walk(root)) {
            return paths.map(root::relativize).filter(path -> !path.toString().isEmpty())
                    .allMatch(path -> path.toString().equals("report.json"));
        }
    }
}
