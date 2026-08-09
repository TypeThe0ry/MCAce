package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Fails if the Fabric product starts linking desktop, process, or input-inspection APIs. */
final class FabricPrivacyBoundaryTest {
    private static final List<String> FORBIDDEN_CONSTANT_POOL_MARKERS = List.of(
            "java/awt/Robot",
            "createScreenCapture",
            "java/awt/Toolkit",
            "com/sun/jna",
            "User32",
            "GetDesktopWindow",
            "GetForegroundWindow",
            "GetAsyncKeyState",
            "SetWindowsHookEx",
            "java/lang/ProcessHandle",
            "getAllProcesses",
            "EnumProcessModules");

    @Test
    void compiledFabricProductDoesNotLinkForbiddenDesktopOrProcessApis() throws Exception {
        Path classes = Path.of(MCAceFabricClient.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
        if (!Files.isDirectory(classes)) {
            fail("Fabric privacy bytecode gate requires the test classes directory");
        }
        try (var paths = Files.walk(classes)) {
            paths.filter(path -> path.getFileName().toString().endsWith(".class"))
                    .forEach(FabricPrivacyBoundaryTest::assertAllowed);
        }
    }

    private static void assertAllowed(Path classFile) {
        try {
            String constants = new String(Files.readAllBytes(classFile), StandardCharsets.ISO_8859_1);
            for (String forbidden : FORBIDDEN_CONSTANT_POOL_MARKERS) {
                if (constants.contains(forbidden)) {
                    fail("forbidden privacy-boundary API " + forbidden + " linked by " + classFile.getFileName());
                }
            }
        } catch (IOException exception) {
            throw new IllegalStateException("cannot inspect compiled Fabric class " + classFile, exception);
        }
    }
}
