package com.ellan.mcace.runtime;

import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Pure, fake-clock-friendly logic shared conceptually with the PowerShell real-process gate. */
final class HostileAdmissionGateLogic {
    private static final Pattern SERVER_BANNER = Pattern.compile(
            "(?m)\\[bootstrap\\] Loading (?<platform>Paper|Folia) [^\\r\\n]*"
                    + " for Minecraft (?<version>(?:1\\.21\\.[0-9]+|26\\.[0-9]+(?:\\.[0-9]+)?))\\s*$");

    private HostileAdmissionGateLogic() {
    }

    static BannerResult validateBanner(String log, String expectedPlatform, String expectedVersion) {
        Objects.requireNonNull(log, "log");
        Matcher matcher = SERVER_BANNER.matcher(log);
        boolean found = false;
        while (matcher.find()) {
            found = true;
            if (!matcher.group("platform").equalsIgnoreCase(expectedPlatform)) {
                return BannerResult.PLATFORM_MISMATCH;
            }
            if (!matcher.group("version").equals(expectedVersion)) {
                return BannerResult.VERSION_MISMATCH;
            }
        }
        return found ? BannerResult.VERIFIED : BannerResult.MISSING;
    }

    static GradleArgsResult validateGradleArguments(List<String> arguments) {
        Objects.requireNonNull(arguments, "arguments");
        return arguments.contains("--offline")
                && arguments.contains("--no-daemon")
                && arguments.contains("--max-workers=1")
                ? GradleArgsResult.VERIFIED
                : GradleArgsResult.REQUIRED_OFFLINE_ARGUMENT_MISSING;
    }

    static ProcessApiResult validateProcessApi(
            boolean argumentListAvailable, boolean processTreeKillAvailable, boolean commandHostAvailable) {
        return argumentListAvailable && processTreeKillAvailable && commandHostAvailable
                ? ProcessApiResult.SUPPORTED
                : ProcessApiResult.POWERSHELL_PROCESS_API_UNSUPPORTED;
    }

    static BuildEvidenceResult validateBuildEvidence(
            boolean processStarted,
            boolean processExitedZero,
            boolean successMarkersSeen,
            long paperBeforeMillis,
            long paperAfterMillis,
            long observerBeforeMillis,
            long observerAfterMillis) {
        if (!processStarted) return BuildEvidenceResult.PROCESS_NOT_STARTED;
        if (!processExitedZero) return BuildEvidenceResult.PROCESS_NOT_ZERO;
        if (!successMarkersSeen) return BuildEvidenceResult.SUCCESS_MARKERS_MISSING;
        if (paperAfterMillis <= paperBeforeMillis) return BuildEvidenceResult.PAPER_OUTPUT_NOT_REFRESHED;
        if (observerAfterMillis <= observerBeforeMillis) {
            return BuildEvidenceResult.OBSERVER_OUTPUT_NOT_REFRESHED;
        }
        return BuildEvidenceResult.VERIFIED;
    }

    static String fixedInternalFailure(FailureStage stage) {
        return Objects.requireNonNull(stage, "stage").name() + "_INTERNAL_ERROR";
    }

    static ReadyMarkers readyMarkers(String log, String platform) {
        Objects.requireNonNull(log, "log");
        Objects.requireNonNull(platform, "platform");
        return new ReadyMarkers(
                log.contains("MCAce signed proxy admission channel enabled"),
                log.contains("MCAce task runtime=" + platform.toUpperCase(java.util.Locale.ROOT)),
                log.contains("MCACE_RUNTIME_OBSERVER_READY"),
                log.contains("Done ("));
    }

    enum BannerResult {
        VERIFIED,
        MISSING,
        PLATFORM_MISMATCH,
        VERSION_MISMATCH
    }

    enum GradleArgsResult {
        VERIFIED,
        REQUIRED_OFFLINE_ARGUMENT_MISSING
    }

    enum ProcessApiResult {
        SUPPORTED,
        POWERSHELL_PROCESS_API_UNSUPPORTED
    }

    enum BuildEvidenceResult {
        VERIFIED,
        PROCESS_NOT_STARTED,
        PROCESS_NOT_ZERO,
        SUCCESS_MARKERS_MISSING,
        PAPER_OUTPUT_NOT_REFRESHED,
        OBSERVER_OUTPUT_NOT_REFRESHED
    }

    enum FailureStage {
        PREFLIGHT,
        OFFLINE_BUILD,
        PREPARE_WORK,
        KEYGEN,
        START_SERVER,
        WAIT_READY,
        VERIFY_VERSION,
        CASE,
        CLEANUP
    }

    record ReadyMarkers(
            boolean admissionChannel,
            boolean runtime,
            boolean observer,
            boolean serverDone) {
    }

    enum WindowResult {
        WAITING,
        STABLE,
        COUNTER_ROLLBACK,
        UNEXPECTED_MARKER,
        TIMEOUT
    }

    record MarkerCounts(long accepted, long cleanup, long localAction) {
        MarkerCounts {
            if (accepted < 0 || cleanup < 0 || localAction < 0) {
                throw new IllegalArgumentException("marker counts must be non-negative");
            }
        }

        MarkerCounts plus(MarkerCounts delta) {
            return new MarkerCounts(
                    Math.addExact(accepted, delta.accepted),
                    Math.addExact(cleanup, delta.cleanup),
                    Math.addExact(localAction, delta.localAction));
        }
    }

    static final class StableMarkerWindow {
        private final MarkerCounts baseline;
        private final MarkerCounts expected;
        private final long deadlineMillis;
        private final long stableDurationMillis;
        private long stableSinceMillis = -1L;

        StableMarkerWindow(
                MarkerCounts baseline,
                MarkerCounts expectedDelta,
                long startedAtMillis,
                long timeoutMillis,
                long stableDurationMillis) {
            this.baseline = Objects.requireNonNull(baseline, "baseline");
            this.expected = baseline.plus(Objects.requireNonNull(expectedDelta, "expectedDelta"));
            if (startedAtMillis < 0 || timeoutMillis <= 0 || stableDurationMillis <= 0
                    || stableDurationMillis > timeoutMillis) {
                throw new IllegalArgumentException("invalid marker-window timing");
            }
            this.deadlineMillis = Math.addExact(startedAtMillis, timeoutMillis);
            this.stableDurationMillis = stableDurationMillis;
        }

        WindowResult observe(long nowMillis, MarkerCounts actual) {
            Objects.requireNonNull(actual, "actual");
            if (actual.accepted() < baseline.accepted()
                    || actual.cleanup() < baseline.cleanup()
                    || actual.localAction() < baseline.localAction()) {
                return WindowResult.COUNTER_ROLLBACK;
            }
            if (actual.accepted() > expected.accepted()
                    || actual.cleanup() > expected.cleanup()
                    || actual.localAction() > expected.localAction()) {
                return WindowResult.UNEXPECTED_MARKER;
            }
            if (!actual.equals(expected)) {
                stableSinceMillis = -1L;
                return nowMillis >= deadlineMillis ? WindowResult.TIMEOUT : WindowResult.WAITING;
            }
            if (stableSinceMillis < 0) {
                stableSinceMillis = nowMillis;
            }
            if (nowMillis - stableSinceMillis >= stableDurationMillis) {
                return WindowResult.STABLE;
            }
            return nowMillis >= deadlineMillis ? WindowResult.TIMEOUT : WindowResult.WAITING;
        }
    }
}
