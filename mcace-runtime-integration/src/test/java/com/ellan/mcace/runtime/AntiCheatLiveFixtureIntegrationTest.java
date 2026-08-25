package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * Executes the owned cheat fixture through a real child JVM and checks client/server sync.
 *
 * <p>This is deliberately separate from the metadata-only fixture smoke: it proves executable
 * fixture loading, client mod-list reporting, independent server behavior detection, same-session
 * correlation, and signed-policy quarantine without loading third-party code or touching a live
 * public server.</p>
 */
final class AntiCheatLiveFixtureIntegrationTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    @Timeout(60)
    void executedCheatFixtureIsCorrelatedAndBenignClientIsNot() throws Exception {
        for (String version : List.of("1.21.11", "26.1.2", "26.2")) {
            Path fixture = createFixture(version);
            Process server = process("server", fixture.toString(), "2").start();
            try {
                BufferedReader serverOutput = new BufferedReader(new InputStreamReader(
                        server.getInputStream(), StandardCharsets.UTF_8));
                String ready = serverOutput.readLine();
                if (ready == null || !ready.startsWith("READY|")) {
                    throw new AssertionError("server did not become ready; first=" + ready
                            + ", remainder=" + serverOutput.lines().toList());
                }
                int port = Integer.parseInt(ready.substring("READY|".length()));

                Process cheat = process(
                        "client", Integer.toString(port), fixture.toString(),
                        "CHEAT_" + version.replace('.', '_'),
                        UUID.nameUUIDFromBytes(("cheat-" + version).getBytes(StandardCharsets.UTF_8)).toString(),
                        "cheat").start();
                assertEquals(0, waitFor(cheat, 10), readAll(cheat));

                Process benign = process(
                        "client", Integer.toString(port), fixture.toString(),
                        "CLEAN_" + version.replace('.', '_'),
                        UUID.nameUUIDFromBytes(("clean-" + version).getBytes(StandardCharsets.UTF_8)).toString(),
                        "clean").start();
                assertEquals(0, waitFor(benign, 10), readAll(benign));

                assertTrue(server.waitFor(10, TimeUnit.SECONDS), "anti-cheat fixture server timed out");
                List<String> lines = serverOutput.lines().toList();
                assertEquals(0, server.exitValue(), lines.toString());
                String cheatResult = lines.stream()
                        .filter(line -> line.startsWith("RESULT|CHEAT_"))
                        .findFirst()
                        .orElseThrow(() -> new AssertionError("missing cheat result: " + lines));
                String cleanResult = lines.stream()
                        .filter(line -> line.startsWith("RESULT|CLEAN_"))
                        .findFirst()
                        .orElseThrow(() -> new AssertionError("missing clean result: " + lines));

                assertResult(cheatResult, "SERVER_CONFIRMED", "QUARANTINE", true, true,
                        "mcace-fixture-server", "Simulation", "CLIENT_REPORTED", true);
                assertResult(cleanResult, "NO_CORRELATION", "OBSERVE", false, false,
                        "none", "none", "none", false);
            } finally {
                destroy(server);
            }
        }
        System.out.println("ANTICHEAT_LIVE_FIXTURE_INTEGRATION_PASS|versions=3|executed=true|server_confirmed=3|clean_false_positive=0");
    }

    private ProcessBuilder process(String... arguments) {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String classpath = System.getProperty("mcace.anticheat.fixture.classpath");
        if (classpath == null || classpath.isBlank()) {
            throw new IllegalStateException("mcace.anticheat.fixture.classpath is not configured");
        }
        List<String> command = new ArrayList<>();
        command.add(java);
        command.add("-Xms16m");
        command.add("-Xmx128m");
        command.add("-cp");
        command.add(classpath);
        command.add(AntiCheatLiveFixtureMain.class.getName());
        command.addAll(List.of(arguments));
        return new ProcessBuilder(command).redirectErrorStream(true);
    }

    private Path createFixture(String version) throws IOException {
        Path fixture = temporaryDirectory.resolve("mcace-test-cheat-" + version + ".jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(fixture))) {
            writeEntry(output, "fabric.mod.json", ("{\"schemaVersion\":1,\"id\":\"mcace-test-cheat\","
                    + "\"version\":\"" + version + "\",\"entrypoints\":{\"client\":["
                    + "\"com.ellan.mcace.runtime.ControlledCheatEntrypoint\"]}}\n")
                    .getBytes(StandardCharsets.UTF_8));
            try (var input = AntiCheatLiveFixtureIntegrationTest.class.getResourceAsStream(
                    "/com/ellan/mcace/runtime/ControlledCheatEntrypoint.class")) {
                if (input == null) throw new IOException("controlled cheat entrypoint class is missing");
                writeEntry(output, "com/ellan/mcace/runtime/ControlledCheatEntrypoint.class", input.readAllBytes());
            }
        }
        return fixture;
    }

    private static void writeEntry(JarOutputStream output, String name, byte[] bytes) throws IOException {
        output.putNextEntry(new JarEntry(name));
        output.write(bytes);
        output.closeEntry();
    }

    private static int waitFor(Process process, int seconds) throws Exception {
        if (!process.waitFor(seconds, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IOException("anti-cheat fixture child process timed out");
        }
        return process.exitValue();
    }

    private static String readAll(Process process) throws IOException {
        return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void destroy(Process process) throws Exception {
        if (process.isAlive()) process.destroyForcibly();
        process.waitFor(2, TimeUnit.SECONDS);
    }

    private static void assertResult(
            String line,
            String origin,
            String action,
            boolean authorized,
            boolean correlated,
            String provider,
            String signal,
            String clientOrigin,
            boolean impossibleMovement) {
        String[] fields = line.split("\\|", -1);
        assertEquals(10, fields.length, line);
        assertEquals(origin, fields[2], line);
        assertEquals(action, fields[3], line);
        assertEquals(Boolean.toString(authorized), fields[4], line);
        assertEquals(Boolean.toString(correlated), fields[5], line);
        assertEquals(provider, fields[6], line);
        assertEquals(signal, fields[7], line);
        assertEquals(clientOrigin, fields[8], line);
        assertEquals(Boolean.toString(impossibleMovement), fields[9], line);
        if ("SERVER_CONFIRMED".equals(origin)) {
            assertTrue(authorized, line);
            assertTrue(correlated, line);
        } else {
            assertFalse(authorized, line);
            assertFalse(correlated, line);
        }
    }
}
