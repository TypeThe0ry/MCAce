package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.Test;

final class TrustedDispositionAuthorizationEvidenceLogicTest {
    private static final UUID AUTHORIZATION =
            UUID.fromString("00000000-0000-0000-0000-000000000042");
    private static final String JOURNAL = "v3\t" + AUTHORIZATION
            + "\t00000000-0000-0000-0000-000000000001\t1786118400000\t"
            + "11".repeat(32) + "\t" + "22".repeat(32) + "\t" + "33".repeat(32)
            + "\tADMIN_REVIEWED\tconsole\tCASE-42\tLIMIT\truntime-synthetic-exact"
            + "\tACTIVE\truntime-synthetic-v1\t1\t1786204800000";
    private static final String LEGACY_V2_JOURNAL = AUTHORIZATION
            + "\t00000000-0000-0000-0000-000000000001\t1786118400000\t"
            + "11".repeat(32) + "\t" + "22".repeat(32)
            + "\tADMIN_REVIEWED\tconsole\tCASE-42\tLIMIT\truntime-synthetic-exact"
            + "\tACTIVE\truntime-synthetic-v1\t1\t1786204800000";
    private static final String COMMAND = "MCAce: disposition review authorized action=LIMIT "
            + "rule=runtime-synthetic-exact policy-sequence=1 authorization=" + AUTHORIZATION
            + " session-bound=true execution-context-bound=true execution-queued=true";
    private static final String DURABLE = "MCAce trusted disposition authorization persisted: authorization="
            + AUTHORIZATION + " journal-durable=true execution-context-bound=true "
            + "player=x action=LIMIT policy-sequence=1";
    private static final String EXECUTED = "MCAce manifest disposition: action=LIMIT "
            + "result=LIMITED_DISPATCHED player=x authorization=" + AUTHORIZATION
            + " session-bound=true execution-context-bound=true";

    @Test
    void acceptsOnlyTheSameDurablyPersistedAuthorizationBeforeExecution() {
        assertTrue(MinecraftProxyPlayerProbeTest.ProbeHarness
                .trustedDispositionAuthorizationChainObservedForTest(
                        COMMAND + "\n" + DURABLE + "\n" + EXECUTED,
                        JOURNAL, "LIMIT", MinecraftProxyPlayerProbeTest.ProxyKind.VELOCITY));
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .trustedDispositionAuthorizationChainObservedForTest(
                        COMMAND + "\n" + EXECUTED + "\n" + DURABLE,
                        JOURNAL, "LIMIT", MinecraftProxyPlayerProbeTest.ProxyKind.VELOCITY));
    }

    @Test
    void rejectsJournalOrExecutionFromAnotherAuthorization() {
        UUID other = UUID.fromString("00000000-0000-0000-0000-000000000043");
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .trustedDispositionAuthorizationChainObservedForTest(
                        COMMAND + "\n" + DURABLE + "\n" + EXECUTED.replace(AUTHORIZATION.toString(), other.toString()),
                        JOURNAL, "LIMIT", MinecraftProxyPlayerProbeTest.ProxyKind.VELOCITY));
        assertFalse(MinecraftProxyPlayerProbeTest.ProbeHarness
                .trustedDispositionAuthorizationChainObservedForTest(
                        COMMAND + "\n" + DURABLE + "\n" + EXECUTED,
                        JOURNAL.replace(AUTHORIZATION.toString(), other.toString()),
                        "LIMIT", MinecraftProxyPlayerProbeTest.ProxyKind.VELOCITY));
    }

    @Test
    void rejectsLegacyV2AndMalformedV3JournalRows() {
        String output = COMMAND + "\n" + DURABLE + "\n" + EXECUTED;
        assertFalse(observed(output, LEGACY_V2_JOURNAL),
                "the former unversioned fourteen-column V2 row must fail closed");
        assertFalse(observed(output, JOURNAL.substring("v3\t".length())),
                "an unversioned fifteen-column row must not be treated as V3");
        assertFalse(observed(output, JOURNAL.replaceFirst("v3\\t", "v2\t")),
                "an explicitly old journal version must fail closed");
        assertFalse(observed(output, JOURNAL.replace("33".repeat(32), "gg".repeat(32))),
                "the execution-context commitment must be a SHA-256 value");
    }

    @Test
    void rejectsAnyMarkerThatDoesNotAssertExecutionContextBinding() {
        assertFalse(observed(
                COMMAND.replace(" execution-context-bound=true", "")
                        + "\n" + DURABLE + "\n" + EXECUTED, JOURNAL));
        assertFalse(observed(
                COMMAND + "\n" + DURABLE.replace(" execution-context-bound=true", "")
                        + "\n" + EXECUTED, JOURNAL));
        assertFalse(observed(
                COMMAND + "\n" + DURABLE + "\n"
                        + EXECUTED.replace(" execution-context-bound=true", ""), JOURNAL));
    }

    private static boolean observed(String output, String journal) {
        return MinecraftProxyPlayerProbeTest.ProbeHarness
                .trustedDispositionAuthorizationChainObservedForTest(
                        output, journal, "LIMIT", MinecraftProxyPlayerProbeTest.ProxyKind.VELOCITY);
    }
}
