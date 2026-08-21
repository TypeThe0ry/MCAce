package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertFalse;
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
    private static final String TRUSTED_OPT_IN = "mcace.runtime.trusted-disposition.enabled";
    private static final String TRUSTED_AUTHORIZATION_CONTRACT = "UUID_CONTEXT_COMMITMENT_V3";

    @Test
    void clientReportedDenyReportContractIsAdvisoryWithoutStartingProcesses() {
        var velocity = new MinecraftProxyPlayerProbeTest.DispositionCaseOutcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_DENY,
                true, true, true, true, true, true, false, false, false,
                MinecraftProxyPlayerProbeTest.RouteCompletion.NONE, true, true, true);
        assertTrue(velocity.passed());
        String velocityReport = phaseTwoVelocityJson(velocity);
        assertTrue(velocityReport.contains("\"case\": \"ENFORCE_DENY\""));
        assertTrue(velocityReport.contains("\"configured_execution_mode\": \"LIMITED_ROUTE\""));
        assertTrue(velocityReport.contains("\"requested_policy_action\": \"DISPOSITION_DENY\""));
        assertTrue(velocityReport.contains("\"expected_backend\": \"LOBBY\""));
        assertTrue(velocityReport.contains("\"any_route_lifecycle_observed\": false"));
        assertTrue(velocityReport.contains("\"current_connection_retained\": true"));
        assertTrue(velocityReport.contains("\"current_connection_closed\": false"));

        var contaminatedVelocity = new MinecraftProxyPlayerProbeTest.DispositionCaseOutcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_DENY,
                true, true, true, true, true, true, false, false, true,
                MinecraftProxyPlayerProbeTest.RouteCompletion.NONE, true, true, true);
        assertFalse(contaminatedVelocity.passed(),
                "a DENY route lifecycle must fail the advisory-origin case");

        var bungee = new MinecraftProxyPlayerProbeTest.BungeeDispositionCaseOutcome(
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_DENY,
                true, true, MinecraftProxyPlayerProbeTest.PublisherGate.ACTIVE,
                true, true, true,
                MinecraftProxyPlayerProbeTest.ServerHelloStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthOutboundStage.CONFIGURATION,
                MinecraftProxyPlayerProbeTest.AuthResultStage.ACCEPTED_CONFIGURATION,
                true, false, false, false, true, false, false,
                MinecraftProxyPlayerProbeTest.RouteCompletion.NONE,
                MinecraftProxyPlayerProbeTest.RemoteLiveness.QUIET_TIMEOUT,
                true, true, true);
        assertTrue(bungee.passed());
        String bungeeReport = phaseTwoBungeeJson(bungee);
        assertTrue(bungeeReport.contains("\"case\": \"ENFORCE_DENY\""));
        assertTrue(bungeeReport.contains("\"requested_policy_action\": \"DISPOSITION_DENY\""));
        assertTrue(bungeeReport.contains("\"current_connection_closed\": false"));
        assertTrue(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_DENY
                .actionName().equals("DENY"));
    }

    @Test
    void trustedReportContractRequiresContextCommitmentV3WithoutStartingProcesses() {
        var outcome = new MinecraftProxyPlayerProbeTest.TrustedDispositionCaseOutcome(
                MinecraftProxyPlayerProbeTest.ProxyKind.VELOCITY,
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT,
                true, true, true, true, true, true, true, true, true, true, false,
                MinecraftProxyPlayerProbeTest.RouteCompletion.SUCCESS, true, true, true);
        assertTrue(outcome.passed());
        String report = trustedDispositionJson(outcome);
        assertTrue(report.contains(
                "\"authorization_contract\": \"UUID_CONTEXT_COMMITMENT_V3\""));
        assertFalse(report.contains("UUID_COMMITMENT_V2"));
    }

    @Test
    @Timeout(360)
    void velocityMonitorLimitClientReportedManifestRemainsAdvisory() throws Exception {
        runVelocity(MinecraftProxyPlayerProbeTest.DispositionScenario.MONITOR_LIMIT);
    }

    @Test
    @Timeout(360)
    void velocityEnforceLimitClientReportedManifestRemainsAdvisory() throws Exception {
        runVelocity(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT);
    }

    @Test
    @Timeout(360)
    void velocityEnforceQuarantineClientReportedManifestRemainsAdvisory() throws Exception {
        runVelocity(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_QUARANTINE);
    }

    @Test
    @Timeout(360)
    void velocityEnforceDenyClientReportedManifestRemainsAdvisory() throws Exception {
        runVelocity(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_DENY);
    }

    @Test
    @Timeout(360)
    void bungeeMonitorLimitClientReportedManifestRemainsAdvisory() throws Exception {
        runBungee(MinecraftProxyPlayerProbeTest.DispositionScenario.MONITOR_LIMIT);
    }

    @Test
    @Timeout(360)
    void bungeeEnforceLimitClientReportedManifestRemainsAdvisory() throws Exception {
        runBungee(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT);
    }

    @Test
    @Timeout(360)
    void bungeeEnforceQuarantineClientReportedManifestRemainsAdvisory() throws Exception {
        runBungee(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_QUARANTINE);
    }

    @Test
    @Timeout(360)
    void bungeeEnforceDenyClientReportedManifestRemainsAdvisory() throws Exception {
        runBungee(MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_DENY);
    }

    @Test
    @Timeout(360)
    void velocityAdministratorReviewedExactHashCanRouteLimit() throws Exception {
        runTrusted(MinecraftProxyPlayerProbeTest.ProxyKind.VELOCITY,
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT);
    }

    @Test
    @Timeout(360)
    void velocityAdministratorReviewedExactHashCanRouteQuarantine() throws Exception {
        runTrusted(MinecraftProxyPlayerProbeTest.ProxyKind.VELOCITY,
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_QUARANTINE);
    }

    @Test
    @Timeout(360)
    void bungeeAdministratorReviewedExactHashCanRouteLimit() throws Exception {
        runTrusted(MinecraftProxyPlayerProbeTest.ProxyKind.BUNGEE,
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_LIMIT);
    }

    @Test
    @Timeout(360)
    void bungeeAdministratorReviewedExactHashCanRouteQuarantine() throws Exception {
        runTrusted(MinecraftProxyPlayerProbeTest.ProxyKind.BUNGEE,
                MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_QUARANTINE);
    }

    @Test
    @Timeout(420)
    void velocityAdministratorReviewedDenyClosesOnlyCurrentConnectionAndAllowsCleanReconnect()
            throws Exception {
        trustedOptIn();
        MinecraftProxyPlayerProbeTest.DenyReconnectOutcome outcome =
                MinecraftProxyPlayerProbeTest.runVelocityDenyReconnectCase();
        Path reportRoot = trustedReportRoot(repositoryRoot(), "velocity-enforce_deny_reconnect");
        String report = phaseTwoVelocityDenyReconnectJson(outcome);
        Files.writeString(reportRoot.resolve("report.json"), report, StandardCharsets.UTF_8);
        assertTrue(onlySanitizedReport(reportRoot), "matrix run retained non-report material");
        assertTrue(outcome.passed(), report);
    }

    @Test
    @Timeout(420)
    void bungeeAdministratorReviewedDenyClosesOnlyCurrentConnectionAndAllowsCleanReconnect()
            throws Exception {
        trustedOptIn();
        MinecraftProxyPlayerProbeTest.BungeeDenyReconnectOutcome outcome =
                MinecraftProxyPlayerProbeTest.runBungeeTrustedDenyReconnectCase();
        Path reportRoot = trustedReportRoot(repositoryRoot(), "bungee-enforce_deny_reconnect");
        String report = trustedBungeeDenyReconnectJson(outcome);
        Files.writeString(reportRoot.resolve("report.json"), report, StandardCharsets.UTF_8);
        assertTrue(onlySanitizedReport(reportRoot), "trusted DENY run retained non-report material");
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

    private static void runTrusted(
            MinecraftProxyPlayerProbeTest.ProxyKind kind,
            MinecraftProxyPlayerProbeTest.DispositionScenario scenario) throws Exception {
        trustedOptIn();
        MinecraftProxyPlayerProbeTest.TrustedDispositionCaseOutcome outcome =
                MinecraftProxyPlayerProbeTest.runTrustedDispositionCase(kind, scenario);
        Path reportRoot = trustedReportRoot(repositoryRoot(),
                kind.name().toLowerCase() + "-" + scenario.name().toLowerCase());
        String report = trustedDispositionJson(outcome);
        Files.writeString(reportRoot.resolve("report.json"), report, StandardCharsets.UTF_8);
        assertTrue(onlySanitizedReport(reportRoot), "trusted run retained non-report material");
        assertTrue(outcome.passed(), report);
    }

    private static void optIn() {
        Assumptions.assumeTrue(Boolean.getBoolean(OPT_IN),
                "real proxy disposition matrix is opt-in; set " + OPT_IN + "=true");
    }

    private static void trustedOptIn() {
        Assumptions.assumeTrue(Boolean.getBoolean(TRUSTED_OPT_IN),
                "trusted disposition process gate is opt-in; set " + TRUSTED_OPT_IN + "=true");
    }

    private static Path trustedReportRoot(Path repository, String fixedPrefix) throws Exception {
        Path root = repository.resolve("build/runtime-trusted-disposition/runs")
                .resolve(fixedPrefix + "-" + Instant.now().toString()
                        .replace(':', '-').replace('.', '-'));
        Files.createDirectories(root);
        return root;
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
        return "{\n"
                + "  \"schema\": \"DISPOSITION_ADVISORY_GUARD_MATRIX\",\n"
                + "  \"platform\": \"VELOCITY\",\n"
                + "  \"case\": \"" + outcome.scenario().name() + "\",\n"
                + "  \"configured_execution_mode\": \"" + outcome.scenario().mode() + "\",\n"
                + "  \"requested_policy_action\": \"" + outcome.scenario().policyAction() + "\",\n"
                + "  \"evidence_origin\": \"CLIENT_REPORTED\",\n"
                + "  \"expected_backend\": \"LOBBY\",\n"
                + "  \"forwarding_configured\": " + outcome.forwardingConfigured() + ",\n"
                + "  \"administrator_publisher_active\": " + outcome.publisherActive() + ",\n"
                + "  \"synthetic_exact_manifest_sent\": " + outcome.syntheticManifestSent() + ",\n"
                + "  \"authentication_accepted_any_phase\": " + outcome.authenticationAccepted() + ",\n"
                + "  \"advisory_origin_guard_observed\": "
                + outcome.dispositionResultObserved() + ",\n"
                + "  \"lobby_admission\": " + outcome.lobbyAdmission() + ",\n"
                + "  \"limited_admission\": " + outcome.limitedAdmission() + ",\n"
                + "  \"quarantine_admission\": " + outcome.quarantineAdmission() + ",\n"
                + "  \"any_route_lifecycle_observed\": "
                + outcome.anyRouteLifecycleObserved() + ",\n"
                + "  \"route_completion\": \"" + outcome.routeCompletion().name() + "\",\n"
                + "  \"no_disposition_route_observed\": "
                + (outcome.routeCompletion() == MinecraftProxyPlayerProbeTest.RouteCompletion.NONE) + ",\n"
                + "  \"current_connection_retained\": " + outcome.connectionRetained() + ",\n"
                + "  \"current_connection_closed\": " + !outcome.connectionRetained() + ",\n"
                + "  \"owned_process_cleanup_zero\": " + outcome.cleanupZero() + ",\n"
                + "  \"run_material_removed\": " + outcome.workMaterialRemoved() + ",\n"
                + "  \"server_confirmed_action_process_coverage\": false,\n"
                + "  \"fabric_gui_coverage\": false,\n"
                + "  \"case_passed\": " + outcome.passed() + ",\n"
                + "  \"matrix_completed\": false\n"
                + "}\n";
    }

    static String phaseTwoVelocityDenyReconnectJson(
            MinecraftProxyPlayerProbeTest.DenyReconnectOutcome outcome) {
        return "{\n"
                + "  \"schema\": \"TRUSTED_DENY_RECONNECT_PROCESS_GATE\",\n"
                + "  \"platform\": \"VELOCITY\",\n"
                + "  \"case\": \"ENFORCE_DENY_RECONNECT\",\n"
                + "  \"evidence_origin\": \"ADMIN_REVIEWED\",\n"
                + "  \"review_scope\": \"EXACT_HASH\",\n"
                + "  \"authorization_contract\": \"" + TRUSTED_AUTHORIZATION_CONTRACT + "\",\n"
                + "  \"scope\": \"CURRENT_CONNECTION_THEN_CLEAN_RECONNECT\",\n"
                + "  \"forwarding_configured\": " + outcome.forwardingConfigured() + ",\n"
                + "  \"fixture_login_ratelimit_disabled\": "
                + outcome.fixtureLoginRatelimitDisabled() + ",\n"
                + "  \"administrator_publisher_active\": " + outcome.publisherActive() + ",\n"
                + "  \"first_clean_manifest_sent\": "
                + outcome.firstCleanManifestSent() + ",\n"
                + "  \"first_authentication_accepted\": "
                + outcome.firstAuthenticationAccepted() + ",\n"
                + "  \"first_lobby_verified_admission\": "
                + outcome.firstLobbyVerifiedAdmission() + ",\n"
                + "  \"review_command_sent\": " + outcome.reviewCommandSent() + ",\n"
                + "  \"authorization_observed\": " + outcome.authorizationObserved() + ",\n"
                + "  \"authorization_journal_persisted\": "
                + outcome.authorizationPersisted() + ",\n"
                + "  \"authorization_persisted_before_execution\": "
                + outcome.authorizationPersistedBeforeExecution() + ",\n"
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

    static String trustedBungeeDenyReconnectJson(
            MinecraftProxyPlayerProbeTest.BungeeDenyReconnectOutcome outcome) {
        return "{\n"
                + "  \"schema\": \"TRUSTED_DENY_RECONNECT_PROCESS_GATE\",\n"
                + "  \"platform\": \"BUNGEE\",\n"
                + "  \"case\": \"ENFORCE_DENY_RECONNECT\",\n"
                + "  \"evidence_origin\": \"ADMIN_REVIEWED\",\n"
                + "  \"review_scope\": \"EXACT_HASH\",\n"
                + "  \"authorization_contract\": \"" + TRUSTED_AUTHORIZATION_CONTRACT + "\",\n"
                + "  \"scope\": \"CURRENT_CONNECTION_THEN_CLEAN_RECONNECT\",\n"
                + "  \"forwarding_configured\": " + outcome.forwardingConfigured() + ",\n"
                + "  \"administrator_publisher_active\": " + outcome.publisherActive() + ",\n"
                + "  \"first_clean_manifest_sent\": "
                + outcome.firstCleanManifestSent() + ",\n"
                + "  \"first_authentication_accepted\": "
                + outcome.firstAuthenticationAccepted() + ",\n"
                + "  \"first_lobby_verified_admission\": "
                + outcome.firstLobbyVerifiedAdmission() + ",\n"
                + "  \"review_command_sent\": " + outcome.reviewCommandSent() + ",\n"
                + "  \"authorization_observed\": " + outcome.authorizationObserved() + ",\n"
                + "  \"authorization_journal_persisted\": "
                + outcome.authorizationPersisted() + ",\n"
                + "  \"authorization_persisted_before_execution\": "
                + outcome.authorizationPersistedBeforeExecution() + ",\n"
                + "  \"denied_result_observed\": " + outcome.deniedResultObserved() + ",\n"
                + "  \"first_connection_closed\": " + outcome.firstConnectionClosed() + ",\n"
                + "  \"disconnect_evidence\": \"" + outcome.disconnectEvidence().name() + "\",\n"
                + "  \"proxy_registry_empty_before_reconnect\": "
                + outcome.proxyRegistryEmptyBeforeReconnect() + ",\n"
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
                + "  \"clean_reconnect_outcome\": \"" + outcome.reconnectOutcome() + "\",\n"
                + "  \"owned_process_cleanup_zero\": " + outcome.cleanupZero() + ",\n"
                + "  \"run_material_removed\": " + outcome.workMaterialRemoved() + ",\n"
                + "  \"artifact_content_retained_in_report\": false,\n"
                + "  \"case_passed\": " + outcome.passed() + "\n"
                + "}\n";
    }

    static String phaseTwoBungeeJson(
            MinecraftProxyPlayerProbeTest.BungeeDispositionCaseOutcome outcome) {
        return "{\n"
                + "  \"schema\": \"DISPOSITION_ADVISORY_GUARD_MATRIX\",\n"
                + "  \"platform\": \"BUNGEE\",\n"
                + "  \"case\": \"" + outcome.scenario().name() + "\",\n"
                + "  \"configured_execution_mode\": \"" + outcome.scenario().mode() + "\",\n"
                + "  \"requested_policy_action\": \"" + outcome.scenario().policyAction() + "\",\n"
                + "  \"evidence_origin\": \"CLIENT_REPORTED\",\n"
                + "  \"expected_backend\": \"LOBBY\",\n"
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
                + "  \"advisory_origin_guard_observed\": "
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
                + "  \"current_connection_closed\": " + !outcome.connectionRetained() + ",\n"
                + "  \"owned_process_cleanup_zero\": " + outcome.cleanupZero() + ",\n"
                + "  \"run_material_removed\": " + outcome.workMaterialRemoved() + ",\n"
                + "  \"server_confirmed_action_process_coverage\": false,\n"
                + "  \"fabric_gui_coverage\": false,\n"
                + "  \"case_passed\": " + outcome.passed() + ",\n"
                + "  \"matrix_completed\": false\n"
                + "}\n";
    }

    private static String trustedDispositionJson(
            MinecraftProxyPlayerProbeTest.TrustedDispositionCaseOutcome outcome) {
        String expectedBackend = outcome.scenario()
                == MinecraftProxyPlayerProbeTest.DispositionScenario.ENFORCE_QUARANTINE
                ? "QUARANTINE" : "LIMITED";
        return "{\n"
                + "  \"schema\": \"TRUSTED_DISPOSITION_PROCESS_GATE\",\n"
                + "  \"platform\": \"" + outcome.kind().name() + "\",\n"
                + "  \"case\": \"" + outcome.scenario().name() + "\",\n"
                + "  \"evidence_origin\": \"ADMIN_REVIEWED\",\n"
                + "  \"review_scope\": \"EXACT_HASH\",\n"
                + "  \"authorization_contract\": \"" + TRUSTED_AUTHORIZATION_CONTRACT + "\",\n"
                + "  \"expected_backend\": \"" + expectedBackend + "\",\n"
                + "  \"forwarding_configured\": " + outcome.forwardingConfigured() + ",\n"
                + "  \"administrator_publisher_active\": " + outcome.publisherActive() + ",\n"
                + "  \"authentication_accepted\": " + outcome.authenticationAccepted() + ",\n"
                + "  \"review_command_sent\": " + outcome.reviewCommandSent() + ",\n"
                + "  \"authorization_observed\": " + outcome.authorizationObserved() + ",\n"
                + "  \"authorization_journal_persisted\": "
                + outcome.authorizationPersisted() + ",\n"
                + "  \"authorization_persisted_before_execution\": "
                + outcome.authorizationPersistedBeforeExecution() + ",\n"
                + "  \"trusted_disposition_result_observed\": "
                + outcome.dispositionResultObserved() + ",\n"
                + "  \"lobby_admission\": " + outcome.lobbyAdmission() + ",\n"
                + "  \"limited_admission\": " + outcome.limitedAdmission() + ",\n"
                + "  \"quarantine_admission\": " + outcome.quarantineAdmission() + ",\n"
                + "  \"route_completion\": \"" + outcome.routeCompletion().name() + "\",\n"
                + "  \"current_connection_retained\": " + outcome.connectionRetained() + ",\n"
                + "  \"owned_process_cleanup_zero\": " + outcome.cleanupZero() + ",\n"
                + "  \"run_material_removed\": " + outcome.workMaterialRemoved() + ",\n"
                + "  \"artifact_content_retained_in_report\": false,\n"
                + "  \"case_passed\": " + outcome.passed() + "\n"
                + "}\n";
    }

    private static String phaseOneBungeeJson(boolean baseline, boolean cleanupZero) {
        return "{\n"
                + "  \"schema\": \"DISPOSITION_MATRIX_PHASE_ONE\",\n"
                + "  \"platform\": \"BUNGEE\",\n"
                + "  \"real_transport_baseline\": " + baseline + ",\n"
                + "  \"owned_process_cleanup_zero\": " + cleanupZero + ",\n"
                + "  \"advisory_guard_cases\": \"NOT_EXECUTED\",\n"
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
