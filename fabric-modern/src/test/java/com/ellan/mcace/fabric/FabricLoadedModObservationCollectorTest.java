package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.ellan.mcace.client.observation.LoadedModObservation;
import java.nio.file.Path;
import java.util.List;
import net.fabricmc.loader.api.metadata.ModOrigin;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FabricLoadedModObservationCollectorTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void directModsChildExposesOnlyItsBasename() {
        Path game = temporaryDirectory.resolve("game");
        Path jar = game.resolve("mods").resolve("example.jar");

        LoadedModObservation observation = FabricLoadedModObservationCollector.classify(
                "example", "1.2.3", ModOrigin.Kind.PATH, List.of(jar), null, game);

        assertEquals(LoadedModObservation.OriginKind.MODS_FILE, observation.originKind());
        assertEquals("example.jar", observation.originFilename());
        assertEquals("", observation.parentModId());
        assertFalse(observation.originFilename().contains(game.toString()));
    }

    @Test
    void nestedOriginReportsParentIdWithoutAPath() {
        LoadedModObservation observation = FabricLoadedModObservationCollector.classify(
                "nested", "2.0", ModOrigin.Kind.NESTED, List.of(), "parent", temporaryDirectory);

        assertEquals(LoadedModObservation.OriginKind.NESTED, observation.originKind());
        assertEquals("", observation.originFilename());
        assertEquals("parent", observation.parentModId());
    }

    @Test
    void classpathOrExternalPathIsUnknownAndDoesNotLeakItsLocation() {
        Path game = temporaryDirectory.resolve("game");
        Path classpath = temporaryDirectory.resolve("classes");

        LoadedModObservation observation = FabricLoadedModObservationCollector.classify(
                "builtin", "1", ModOrigin.Kind.PATH, List.of(classpath), null, game);

        assertEquals(LoadedModObservation.OriginKind.UNKNOWN, observation.originKind());
        assertEquals("", observation.originFilename());
        assertEquals("", observation.parentModId());
    }
}
