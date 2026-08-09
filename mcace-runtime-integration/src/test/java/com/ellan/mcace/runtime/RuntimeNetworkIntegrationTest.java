package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

final class RuntimeNetworkIntegrationTest {
    private static final int GOOD_CLIENTS = 4;
    private static final List<RuntimeScenario> MALFORMED = List.of(
            RuntimeScenario.REPLAY_CLIENT_HELLO,
            RuntimeScenario.FORGED_CLIENT_SIGNATURE,
            RuntimeScenario.OVERSIZED_FRAME,
            RuntimeScenario.TRUNCATED_FRAME,
            RuntimeScenario.MALFORMED_PROTOBUF,
            RuntimeScenario.OUT_OF_ORDER_AUTH,
            RuntimeScenario.WRONG_PLAYER_UUID,
            RuntimeScenario.UNPINNED_SERVER,
            RuntimeScenario.INCOMPATIBLE_BUILD);

    @TempDir Path temporaryDirectory;

    @Test
    @Timeout(45)
    void isolatesConcurrentGoodAndControlledMalformedClientProcesses() throws Exception {
        int expectedConnections = GOOD_CLIENTS + MALFORMED.size();
        Process server = process("server", Integer.toString(expectedConnections)).start();
        try {
        BufferedReader serverOutput = new BufferedReader(new InputStreamReader(
                server.getInputStream(), StandardCharsets.UTF_8));
        String ready = serverOutput.readLine();
        if (ready == null || !ready.startsWith("READY|")) {
            String remainder = String.join("\n", serverOutput.lines().toList());
            server.waitFor(2, TimeUnit.SECONDS);
            throw new AssertionError("server did not emit READY; first=" + ready + " remainder=" + remainder);
        }
        String[] readyFields = ready.split("\\|", -1);
        int port = Integer.parseInt(readyFields[1]);
        String root = readyFields[2];

        List<ClientSpec> clients = new ArrayList<>();
        for (int index = 0; index < GOOD_CLIENTS; index++) {
            clients.add(new ClientSpec(RuntimeScenario.GOOD, "GOOD_" + index, UUID.randomUUID()));
        }
        for (RuntimeScenario scenario : MALFORMED) {
            clients.add(new ClientSpec(scenario, scenario.name(), UUID.randomUUID()));
        }

        Future<List<String>> serverLines;
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            serverLines = executor.submit(() -> serverOutput.lines().toList());
            List<Future<ClientExit>> exits = new ArrayList<>();
            for (ClientSpec client : clients) {
                exits.add(executor.submit(() -> runClient(port, root, client)));
            }
            for (Future<ClientExit> exit : exits) {
                ClientExit completed = exit.get(15, TimeUnit.SECONDS);
                assertEquals(0, completed.exitCode(), completed.label() + ": " + completed.output());
            }
            assertTrue(server.waitFor(15, TimeUnit.SECONDS), "runtime server did not exit");
        }
        assertEquals(0, server.exitValue());
        List<String> capturedServerLines = serverLines.get(2, TimeUnit.SECONDS);
        Map<String, Result> results = parseResults(capturedServerLines);
        assertEquals(expectedConnections, results.size());
        System.out.println("RUNTIME_NETWORK_REPORT_BEGIN");
        capturedServerLines.forEach(System.out::println);
        System.out.println("RUNTIME_NETWORK_REPORT_END");

        for (int index = 0; index < GOOD_CLIENTS; index++) {
            Result result = results.get("GOOD_" + index);
            assertEquals("VERIFIED", result.admission());
            assertEquals("VERIFIED", result.trust());
            assertEquals(0, result.risk());
            assertFalse(result.violation());
        }
        assertLimited(results, RuntimeScenario.REPLAY_CLIENT_HELLO, 100, true);
        assertLimited(results, RuntimeScenario.FORGED_CLIENT_SIGNATURE, 80, true);
        assertLimited(results, RuntimeScenario.OVERSIZED_FRAME, 80, true);
        assertLimited(results, RuntimeScenario.TRUNCATED_FRAME, 80, true);
        assertLimited(results, RuntimeScenario.MALFORMED_PROTOBUF, 80, true);
        assertLimited(results, RuntimeScenario.OUT_OF_ORDER_AUTH, 80, true);
        assertLimited(results, RuntimeScenario.WRONG_PLAYER_UUID, 50, true);
        assertLimited(results, RuntimeScenario.UNPINNED_SERVER, 20, false);
        assertLimited(results, RuntimeScenario.INCOMPATIBLE_BUILD, 20, false);
        } finally {
            if (server.isAlive()) {
                server.destroyForcibly();
                server.waitFor(2, TimeUnit.SECONDS);
            }
        }
    }

    private ClientExit runClient(int port, String root, ClientSpec client) throws Exception {
        Path cache = temporaryDirectory.resolve(client.label());
        Process process = process(
                "client",
                Integer.toString(port),
                root,
                client.scenario().name(),
                client.label(),
                client.playerId().toString(),
                cache.toString()).start();
        try {
            if (!process.waitFor(12, TimeUnit.SECONDS)) {
                throw new IOException("client process timed out: " + client.label());
            }
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return new ClientExit(client.label(), process.exitValue(), output);
        } finally {
            if (process.isAlive()) process.destroyForcibly();
        }
    }

    private static ProcessBuilder process(String... arguments) {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String classpath = System.getProperty("mcace.runtime.classpath");
        if (classpath == null || classpath.isBlank()) {
            throw new IllegalStateException("mcace.runtime.classpath is not configured");
        }
        List<String> command = new ArrayList<>();
        command.add(java);
        command.add("-Xms16m");
        command.add("-Xmx128m");
        command.add("-cp");
        command.add(classpath);
        command.add(RuntimeNetworkMain.class.getName());
        command.addAll(List.of(arguments));
        return new ProcessBuilder(command).redirectErrorStream(true);
    }

    private static Map<String, Result> parseResults(List<String> lines) {
        Map<String, Result> results = new LinkedHashMap<>();
        for (String line : lines) {
            if (line.startsWith("SERVER_ERROR|")) {
                throw new AssertionError(line);
            }
            if (!line.startsWith("RESULT|")) continue;
            String[] fields = line.split("\\|", -1);
            Result previous = results.put(fields[1], new Result(
                    fields[2], fields[3], Integer.parseInt(fields[4]), Boolean.parseBoolean(fields[5])));
            if (previous != null) throw new AssertionError("duplicate runtime result: " + fields[1]);
        }
        return results;
    }

    private static void assertLimited(
            Map<String, Result> results,
            RuntimeScenario scenario,
            int risk,
            boolean violation) {
        Result result = results.get(scenario.name());
        assertEquals("LIMITED", result.admission());
        assertEquals("UNKNOWN", result.trust());
        assertEquals(risk, result.risk());
        assertEquals(violation, result.violation());
    }

    private record ClientSpec(RuntimeScenario scenario, String label, UUID playerId) { }
    private record ClientExit(String label, int exitCode, String output) { }
    private record Result(String admission, String trust, int risk, boolean violation) { }
}
