package com.ellan.mcace.fabric;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Constant-pool policy applied to the bytes that will actually be deployed. */
final class FabricPrivacyBytecodePolicy {
    private static final List<String> FORBIDDEN_CONSTANT_POOL_MARKERS = List.of(
            "java/awt/Robot",
            "createScreenCapture",
            "java/awt/Toolkit",
            "java/awt/Desktop",
            "java/awt/GraphicsDevice",
            "java/awt/GraphicsEnvironment",
            "com/sun/jna",
            "User32",
            "GetDesktopWindow",
            "GetForegroundWindow",
            "GetAsyncKeyState",
            "SetWindowsHookEx",
            "java/lang/Process",
            "getAllProcesses",
            "EnumProcessModules");

    private FabricPrivacyBytecodePolicy() {}

    static Set<String> violations(byte[] classBytes) {
        String constants = new String(classBytes, StandardCharsets.ISO_8859_1);
        Set<String> violations = new TreeSet<>();
        for (String forbidden : FORBIDDEN_CONSTANT_POOL_MARKERS) {
            if (constants.contains(forbidden)) {
                violations.add(forbidden);
            }
        }
        return violations;
    }
}
