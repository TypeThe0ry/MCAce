package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

final class HostileAdmissionGateLogicTest {
    @Test
    void exactCountsMustRemainUnchangedForWholeStableWindow() {
        var gate = new HostileAdmissionGateLogic.StableMarkerWindow(
                counts(3, 4, 2), counts(0, 1, 0), 1_000L, 5_000L, 2_000L);

        assertEquals(HostileAdmissionGateLogic.WindowResult.WAITING,
                gate.observe(1_100L, counts(3, 5, 2)));
        assertEquals(HostileAdmissionGateLogic.WindowResult.WAITING,
                gate.observe(3_099L, counts(3, 5, 2)));
        assertEquals(HostileAdmissionGateLogic.WindowResult.STABLE,
                gate.observe(3_100L, counts(3, 5, 2)));
    }

    @Test
    void lateOldMarkerCannotBeConsumedByTheNextCase() {
        var gate = new HostileAdmissionGateLogic.StableMarkerWindow(
                counts(8, 8, 4), counts(0, 1, 0), 0L, 5_000L, 1_000L);

        assertEquals(HostileAdmissionGateLogic.WindowResult.UNEXPECTED_MARKER,
                gate.observe(100L, counts(8, 10, 4)));
    }

    @Test
    void missingExpectedMarkerTimesOutWithFakeClock() {
        var gate = new HostileAdmissionGateLogic.StableMarkerWindow(
                counts(0, 0, 0), counts(1, 1, 1), 10L, 100L, 25L);

        assertEquals(HostileAdmissionGateLogic.WindowResult.WAITING,
                gate.observe(109L, counts(0, 1, 0)));
        assertEquals(HostileAdmissionGateLogic.WindowResult.TIMEOUT,
                gate.observe(110L, counts(0, 1, 0)));
    }

    @Test
    void validatesActualPaperAndFoliaBannerShapesAndMismatch() {
        String paper = "[bootstrap] Loading Paper 1.21.1-133-ver/1.21.1@abc for Minecraft 1.21.1\n";
        String folia = "[bootstrap] Loading Folia 1.21.4-6-ver/1.21.4@abc for Minecraft 1.21.4\n";

        assertEquals(HostileAdmissionGateLogic.BannerResult.VERIFIED,
                HostileAdmissionGateLogic.validateBanner(paper, "Paper", "1.21.1"));
        assertEquals(HostileAdmissionGateLogic.BannerResult.VERIFIED,
                HostileAdmissionGateLogic.validateBanner(folia, "Folia", "1.21.4"));
        assertEquals(HostileAdmissionGateLogic.BannerResult.VERSION_MISMATCH,
                HostileAdmissionGateLogic.validateBanner(folia, "Folia", "1.21.1"));
        assertEquals(HostileAdmissionGateLogic.BannerResult.PLATFORM_MISMATCH,
                HostileAdmissionGateLogic.validateBanner(folia, "Paper", "1.21.4"));
    }

    @Test
    void everyGradleInvocationRequiresOfflineAndBoundedWorkerArguments() {
        assertEquals(HostileAdmissionGateLogic.GradleArgsResult.VERIFIED,
                HostileAdmissionGateLogic.validateGradleArguments(
                        List.of("task", "--offline", "--no-daemon", "--max-workers=1")));
        assertEquals(HostileAdmissionGateLogic.GradleArgsResult.REQUIRED_OFFLINE_ARGUMENT_MISSING,
                HostileAdmissionGateLogic.validateGradleArguments(
                        List.of("task", "--no-daemon", "--max-workers=1")));
    }

    @Test
    void rejectsWindowsPowerShellWithoutRequiredProcessApisBeforeRunnerUse() {
        assertEquals(HostileAdmissionGateLogic.ProcessApiResult.POWERSHELL_PROCESS_API_UNSUPPORTED,
                HostileAdmissionGateLogic.validateProcessApi(false, false, true));
        assertEquals(HostileAdmissionGateLogic.ProcessApiResult.SUPPORTED,
                HostileAdmissionGateLogic.validateProcessApi(true, true, true));
    }

    @Test
    void stalePreexistingJarsCannotSatisfyCurrentBuildEvidence() {
        assertEquals(HostileAdmissionGateLogic.BuildEvidenceResult.PAPER_OUTPUT_NOT_REFRESHED,
                HostileAdmissionGateLogic.validateBuildEvidence(
                        true, true, true, 100L, 100L, 100L, 101L));
        assertEquals(HostileAdmissionGateLogic.BuildEvidenceResult.OBSERVER_OUTPUT_NOT_REFRESHED,
                HostileAdmissionGateLogic.validateBuildEvidence(
                        true, true, true, 100L, 101L, 100L, 100L));
        assertEquals(HostileAdmissionGateLogic.BuildEvidenceResult.VERIFIED,
                HostileAdmissionGateLogic.validateBuildEvidence(
                        true, true, true, 100L, 101L, 100L, 101L));
    }

    @Test
    void unknownSystemErrorsBecomeFixedStageEnums() {
        assertEquals("OFFLINE_BUILD_INTERNAL_ERROR",
                HostileAdmissionGateLogic.fixedInternalFailure(
                        HostileAdmissionGateLogic.FailureStage.OFFLINE_BUILD));
        assertEquals("START_SERVER_INTERNAL_ERROR",
                HostileAdmissionGateLogic.fixedInternalFailure(
                        HostileAdmissionGateLogic.FailureStage.START_SERVER));
    }

    @Test
    void readyMarkerStatusIsContentFreeBooleans() {
        var markers = HostileAdmissionGateLogic.readyMarkers(
                "MCAce signed proxy admission channel enabled\n"
                        + "MCAce task runtime=PAPER\nDone (1.0s)\n",
                "Paper");
        assertTrue(markers.admissionChannel());
        assertTrue(markers.runtime());
        assertFalse(markers.observer());
        assertTrue(markers.serverDone());
    }

    @Test
    void wrapperUsesOfflineTimedProcessRunnerAndNoAcquisitionSmoke() throws Exception {
        Path root = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        while (root != null && !Files.isRegularFile(root.resolve("settings.gradle.kts"))) {
            root = root.getParent();
        }
        assertTrue(root != null, "repository root unavailable");
        String script = Files.readString(root.resolve(
                "scripts/paper-folia-hostile-admission-smoke.ps1"));

        assertTrue(script.contains("Invoke-OfflineGradle"));
        assertTrue(script.contains("Assert-RequiredProcessApi"));
        assertTrue(script.contains("POWERSHELL_PROCESS_API_UNSUPPORTED"));
        assertTrue(script.contains("'--offline'"));
        assertTrue(script.contains("WaitForExit($TimeoutSeconds * 1000)"));
        assertTrue(script.contains("$process.Kill($true)"));
        assertTrue(script.contains("PAPER_BUILD_OUTPUT_NOT_REFRESHED"));
        assertTrue(script.contains("OBSERVER_BUILD_OUTPUT_NOT_REFRESHED"));
        assertTrue(script.contains("failure_stage = $failureStage"));
        assertFalse(script.contains("UNCLASSIFIED_FAILURE"));
        assertFalse(script.contains("folia-process-smoke.ps1"));
        assertFalse(script.matches("(?s).*&\\s+[^\\r\\n]*gradle(?:w)?(?:\\.bat)?.*"));
    }

    private static HostileAdmissionGateLogic.MarkerCounts counts(
            long accepted, long cleanup, long action) {
        return new HostileAdmissionGateLogic.MarkerCounts(accepted, cleanup, action);
    }
}
