package com.ellan.mcace.client.observation;

import java.util.Objects;

/**
 * Privacy-bounded description of one mod in Fabric Loader's actual runtime graph.
 *
 * <p>No absolute origin path is retained.  A direct {@code mods/} origin exposes only its
 * basename; nested mods expose only the parent mod id; classpath/builtin origins expose neither.
 */
public record LoadedModObservation(
        String id,
        String version,
        OriginKind originKind,
        String originFilename,
        String parentModId) {

    public LoadedModObservation {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(originKind, "originKind");
        Objects.requireNonNull(originFilename, "originFilename");
        Objects.requireNonNull(parentModId, "parentModId");
    }

    public enum OriginKind {
        MODS_FILE,
        NESTED,
        BUILTIN_OR_CLASSPATH,
        UNKNOWN
    }
}
