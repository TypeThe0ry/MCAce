package com.ellan.mcace.core.evidence;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Platform-neutral validation for the console-only local evidence review command. */
public final class EvidenceReviewCommandInput {
    public enum Status { ACCEPTED, CONSOLE_ONLY, USAGE, INVALID_EVIDENCE_ID, INVALID_REASON }

    public record Request(UUID evidenceId, String reason) {
        public Request {
            Objects.requireNonNull(evidenceId, "evidenceId");
            reason = Objects.requireNonNull(reason, "reason");
        }
    }

    public record Validation(Status status, Optional<Request> request) {
        public Validation {
            Objects.requireNonNull(status, "status");
            request = Objects.requireNonNull(request, "request");
            if ((status == Status.ACCEPTED) != request.isPresent()) {
                throw new IllegalArgumentException("review command validation/result mismatch");
            }
        }
    }

    private EvidenceReviewCommandInput() {
    }

    /** Arguments include the leading {@code review} subcommand. */
    public static Validation validate(boolean consoleSource, String[] arguments) {
        Objects.requireNonNull(arguments, "arguments");
        if (!consoleSource) return new Validation(Status.CONSOLE_ONLY, Optional.empty());
        if (arguments.length < 3) return new Validation(Status.USAGE, Optional.empty());
        final UUID evidenceId;
        try {
            evidenceId = UUID.fromString(arguments[1]);
        } catch (IllegalArgumentException exception) {
            return new Validation(Status.INVALID_EVIDENCE_ID, Optional.empty());
        }
        String reason = String.join(" ", Arrays.copyOfRange(arguments, 2, arguments.length)).trim();
        if (reason.isEmpty() || reason.length() > 256 || reason.chars().anyMatch(Character::isISOControl)) {
            return new Validation(Status.INVALID_REASON, Optional.empty());
        }
        return new Validation(Status.ACCEPTED, Optional.of(new Request(evidenceId, reason)));
    }
}
