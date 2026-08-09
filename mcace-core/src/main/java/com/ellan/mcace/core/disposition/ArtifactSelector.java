package com.ellan.mcace.core.disposition;

import java.util.Map;
import java.util.Objects;

/** Selector input is deliberately constrained: no executable expressions or regular expressions. */
public record ArtifactSelector(ArtifactType type, MatchType matchType, String value, String minimumVersion,
                               String maximumVersion, Map<String, String> requiredMetadata) {
    public ArtifactSelector {
        Objects.requireNonNull(type, "type"); Objects.requireNonNull(matchType, "matchType");
        Objects.requireNonNull(value, "value"); Objects.requireNonNull(requiredMetadata, "requiredMetadata");
        if (value.isBlank()) throw new IllegalArgumentException("selector value must not be blank");
        if (matchType == MatchType.EXACT_HASH && !value.matches("[A-Fa-f0-9]{64}")) throw new IllegalArgumentException("hash selector must be SHA-256");
        if ((minimumVersion != null && minimumVersion.isBlank()) || (maximumVersion != null && maximumVersion.isBlank())) throw new IllegalArgumentException("versions must not be blank");
        if (minimumVersion != null && maximumVersion != null && compareVersions(minimumVersion, maximumVersion) > 0) throw new IllegalArgumentException("minimumVersion is after maximumVersion");
        requiredMetadata = Map.copyOf(requiredMetadata);
    }
    public boolean matches(ArtifactObservation observation) {
        if (type != observation.type() || !versionMatches(observation.version()) || !observation.metadata().entrySet().containsAll(requiredMetadata.entrySet())) return false;
        return switch (matchType) {
            case EXACT_ID -> value.equals(observation.identifier());
            case EXACT_HASH -> value.equalsIgnoreCase(observation.sha256());
            case PREFIX -> observation.identifier().startsWith(value);
            case METADATA -> observation.metadata().entrySet().containsAll(requiredMetadata.entrySet());
        };
    }
    private boolean versionMatches(String version) { return (minimumVersion == null || compareVersions(version, minimumVersion) >= 0) && (maximumVersion == null || compareVersions(version, maximumVersion) <= 0); }
    static int compareVersions(String a, String b) {
        String[] left = a.split("[.-]", -1), right = b.split("[.-]", -1); int length = Math.max(left.length, right.length);
        for (int i = 0; i < length; i++) { String x = i < left.length ? left[i] : "0", y = i < right.length ? right[i] : "0"; int c;
            try { c = Integer.compare(Integer.parseInt(x), Integer.parseInt(y)); } catch (NumberFormatException ignored) { c = x.compareTo(y); } if (c != 0) return c; }
        return 0;
    }
}
