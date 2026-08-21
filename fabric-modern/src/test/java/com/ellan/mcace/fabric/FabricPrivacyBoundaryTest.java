package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/** Proves the bytecode policy catches forbidden links without rejecting ordinary JDK APIs. */
final class FabricPrivacyBoundaryTest {
    @Test
    void policyRejectsDesktopCaptureJnaAndProcessFixtures() throws Exception {
        assertViolation(ForbiddenRobotFixture.class, "java/awt/Robot");
        assertViolation(ForbiddenDesktopFixture.class, "java/awt/Desktop");
        assertViolation(ForbiddenJnaFixture.class, "com/sun/jna");
        assertViolation(ForbiddenProcessFixture.class, "java/lang/Process");
    }

    @Test
    void policyAllowsOrdinaryJdkApis() throws Exception {
        assertEquals(Set.of(), FabricPrivacyBytecodePolicy.violations(classBytes(AllowedJdkFixture.class)));
    }

    private static void assertViolation(Class<?> fixture, String marker) throws IOException {
        Set<String> violations = FabricPrivacyBytecodePolicy.violations(classBytes(fixture));
        assertTrue(violations.contains(marker), () -> fixture.getSimpleName() + " was not rejected: " + violations);
    }

    private static byte[] classBytes(Class<?> type) throws IOException {
        String resource = "/" + type.getName().replace('.', '/') + ".class";
        try (InputStream input = type.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IOException("missing fixture bytecode " + resource);
            }
            return input.readAllBytes();
        }
    }

    private static final class ForbiddenRobotFixture {
        private java.awt.Robot robot;
    }

    private static final class ForbiddenDesktopFixture {
        private java.awt.Desktop desktop;
    }

    private static final class ForbiddenJnaFixture {
        private static final String NATIVE_CLASS = "com/sun/jna/Native";
    }

    private static final class ForbiddenProcessFixture {
        private ProcessBuilder builder;
        private ProcessHandle handle;
    }

    private static final class AllowedJdkFixture {
        private Path path;
        private MessageDigest digest;
        private CompletableFuture<String> future;
        private RuntimeException failure;
    }
}
