package com.ellan.mcace.fabric;

import com.ellan.mcace.client.observation.LoadedModObservation;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.fabricmc.loader.api.metadata.ModMetadata;
import net.fabricmc.loader.api.metadata.ModOrigin;

/**
 * Reads Fabric Loader's actual runtime graph without exposing absolute origin paths.
 */
final class FabricLoadedModObservationCollector {
    private FabricLoadedModObservationCollector() {
    }

    static List<LoadedModObservation> collect(FabricLoader loader) {
        Objects.requireNonNull(loader, "loader");
        Path gameDirectory = loader.getGameDir();
        return loader.getAllMods().stream()
                .map(mod -> classify(mod, gameDirectory))
                .sorted(Comparator.comparing(LoadedModObservation::id)
                        .thenComparing(LoadedModObservation::version)
                        .thenComparing(observation -> observation.originKind().name())
                        .thenComparing(LoadedModObservation::originFilename)
                        .thenComparing(LoadedModObservation::parentModId))
                .toList();
    }

    private static LoadedModObservation classify(ModContainer container, Path gameDirectory) {
        ModMetadata metadata = container.getMetadata();
        ModOrigin origin = container.getOrigin();
        ModOrigin.Kind kind = origin.getKind();
        return classify(
                metadata.getId(),
                metadata.getVersion().getFriendlyString(),
                kind,
                kind == ModOrigin.Kind.PATH ? origin.getPaths() : List.of(),
                kind == ModOrigin.Kind.NESTED ? origin.getParentModId() : "",
                gameDirectory);
    }

    static LoadedModObservation classify(
            String id,
            String version,
            ModOrigin.Kind kind,
            List<Path> paths,
            String parentModId,
            Path gameDirectory) {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(paths, "paths");
        Objects.requireNonNull(gameDirectory, "gameDirectory");
        String normalizedParent = parentModId == null ? "" : parentModId;
        if (kind == ModOrigin.Kind.PATH) {
            if (paths.size() == 1) {
                Path origin = paths.get(0).toAbsolutePath().normalize();
                Path mods = gameDirectory.resolve("mods").toAbsolutePath().normalize();
                Path filename = origin.getFileName();
                if (filename != null && mods.equals(origin.getParent())) {
                    return new LoadedModObservation(id, version,
                            LoadedModObservation.OriginKind.MODS_FILE,
                            filename.toString(), "");
                }
            }
            // Fabric exposes PATH for both ordinary classpath containers and arbitrary external
            // paths.  Without disclosing the path, we cannot prove which one it is; fail closed
            // to UNKNOWN rather than applying a benign-looking built-in label.
            return new LoadedModObservation(id, version,
                    LoadedModObservation.OriginKind.UNKNOWN, "", "");
        }
        if (kind == ModOrigin.Kind.NESTED) {
            return new LoadedModObservation(id, version,
                    LoadedModObservation.OriginKind.NESTED, "", normalizedParent);
        }
        return new LoadedModObservation(id, version,
                LoadedModObservation.OriginKind.UNKNOWN, "", "");
    }
}
