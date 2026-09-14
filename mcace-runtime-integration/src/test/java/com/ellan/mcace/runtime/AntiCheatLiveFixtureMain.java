package com.ellan.mcace.runtime;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.core.proxy.ServerBehaviorCorrelationResult;
import com.ellan.mcace.core.proxy.ServerBehaviorCorrelationRuntime;
import com.ellan.mcace.core.proxy.ServerBehaviorObservation;
import com.ellan.mcace.core.proxy.ProxyFamily;
import com.ellan.mcace.core.proxy.SharedProxyDispositionPolicyRuntime;
import com.ellan.mcace.core.proxy.TrustedDispositionAuthorizationRecord;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedDispositionPolicyDocument;
import com.ellan.mcace.protocol.policy.DispositionPolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.google.protobuf.ByteString;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Test-only loopback client/server harness for an executed, owned cheat fixture.
 *
 * <p>The client process really loads executable code from a generated JAR and reports its
 * mod-list entry. The server does not trust that label: it independently derives a simulation
 * signal from movement deltas, then uses the production correlation runtime and a signed lab
 * policy to produce a server-confirmed quarantine event.</p>
 */
final class AntiCheatLiveFixtureMain {
    private static final String PROVIDER = "mcace-fixture-server";
    private static final String SIGNAL = "Simulation";
    private static final Duration WINDOW = Duration.ofSeconds(30);
    private static final double IMPOSSIBLE_DELTA = 2.0d;

    private AntiCheatLiveFixtureMain() {
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length == 3 && "server".equals(arguments[0])) {
            runServer(Path.of(arguments[1]), Integer.parseInt(arguments[2]));
            return;
        }
        if (arguments.length == 6 && "client".equals(arguments[0])) {
            runClient(
                    Integer.parseInt(arguments[1]),
                    Path.of(arguments[2]),
                    arguments[3],
                    UUID.fromString(arguments[4]),
                    arguments[5]);
            return;
        }
        throw new IllegalArgumentException(
                "usage: server <fixture-jar> <connections> or client <port> <fixture-jar> "
                        + "<label> <player-uuid> <cheat|clean>");
    }

    private static void runServer(Path fixtureJar, int expectedConnections) throws Exception {
        String fixtureHash = sha256(fixtureJar);
        KeyPair policyIdentity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument policyDocument = signedPolicy(policyIdentity, fixtureHash);
        ArrayList<TrustedDispositionAuthorizationRecord> records = new ArrayList<>();
        SharedProxyDispositionPolicyRuntime policyRuntime = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY,
                () -> policyDocument,
                policyIdentity.getPublic(),
                Clock.systemUTC(),
                WINDOW);
        ServerBehaviorCorrelationRuntime correlationRuntime = new ServerBehaviorCorrelationRuntime(
                policyRuntime,
                records::add,
                Clock.systemUTC(),
                WINDOW,
                Set.of(PROVIDER));

        try (ServerSocket listener = new ServerSocket(0, expectedConnections, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(15_000);
            System.out.println("READY|" + listener.getLocalPort());
            System.out.flush();
            List<Thread> handlers = new ArrayList<>();
            for (int index = 0; index < expectedConnections; index++) {
                Socket socket = listener.accept();
                Thread handler = Thread.ofVirtual().start(() -> handleConnection(
                        socket, fixtureHash, correlationRuntime, records));
                handlers.add(handler);
            }
            for (Thread handler : handlers) {
                handler.join(15_000);
                if (handler.isAlive()) {
                    throw new IOException("anti-cheat fixture server handler did not finish");
                }
            }
        }
    }

    private static void handleConnection(
            Socket socket,
            String expectedFixtureHash,
            ServerBehaviorCorrelationRuntime correlationRuntime,
            List<TrustedDispositionAuthorizationRecord> records) {
        String label = "UNKNOWN";
        try (socket;
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))) {
            socket.setSoTimeout(8_000);
            String hello = reader.readLine();
            if (hello == null) throw new IOException("client closed before HELLO");
            String[] helloFields = split(hello, 4, "HELLO");
            label = helloFields[3];
            UUID player = UUID.fromString(helloFields[1]);
            String session = helloFields[2];
            Instant clientObservedAt = null;
            ArtifactObservation clientObservation = null;
            boolean impossibleMovement = false;
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("MOD|")) {
                    String[] fields = split(line, 5, "MOD");
                    if (!expectedFixtureHash.equals(fields[3])) {
                        throw new IOException("fixture hash did not bind to server policy");
                    }
                    clientObservedAt = Instant.now();
                    clientObservation = new ArtifactObservation(
                            ArtifactType.MOD,
                            fields[1],
                            fields[2],
                            fields[3],
                            Map.of(
                                    "scope", "mods",
                                    "execution_status", fields[4],
                                    "fixture_mode", "CONTROLLED_EXECUTABLE_CLIENT"),
                            ObservationOrigin.CLIENT_REPORTED,
                            Confidence.LOW,
                            false);
                } else if (line.startsWith("MOVE|")) {
                    String[] fields = split(line, 3, "MOVE");
                    double delta = Double.parseDouble(fields[2]);
                    if (Math.abs(delta) > IMPOSSIBLE_DELTA) impossibleMovement = true;
                } else if (line.equals("END")) {
                    break;
                } else {
                    throw new IOException("unexpected anti-cheat fixture frame");
                }
            }

            ServerBehaviorCorrelationResult result = null;
            if (clientObservation != null && impossibleMovement) {
                Instant observedAt = Instant.now();
                result = correlationRuntime.correlate(
                        player,
                        session,
                        new EvaluationContext(
                                player, "velocity", "fixture", "world", "survival", Set.of(), observedAt),
                        clientObservedAt,
                        clientObservation,
                        new ServerBehaviorObservation(player, session, PROVIDER, SIGNAL, observedAt))
                        .orElse(null);
            }

            if (result == null) {
                emit("RESULT|" + label + "|NO_CORRELATION|OBSERVE|false|false|none|none|"
                        + (clientObservation == null ? "none" : "CLIENT_REPORTED") + "|"
                        + (impossibleMovement ? "true" : "false"));
                return;
            }
            String provider = result.correlatedObservation().metadata().get("correlated_provider");
            String signal = result.correlatedObservation().metadata().get("correlated_signal");
            String action = result.evaluation().decision().action().name();
            emit("RESULT|" + label + "|SERVER_CONFIRMED|" + action + "|"
                    + result.authorizedEvent().isPresent() + "|true|" + provider + "|" + signal + "|"
                    + result.correlatedObservation().metadata().get("client_origin") + "|true");
        } catch (Exception exception) {
            emit("ERROR|" + label + "|" + exception.getClass().getSimpleName() + "|"
                    + sanitize(exception.getMessage()));
        }
    }

    private static void emit(String line) {
        synchronized (System.out) {
            System.out.println(line);
            System.out.flush();
        }
    }

    private static void runClient(int port, Path fixtureJar, String label, UUID player, String mode)
            throws Exception {
        boolean cheat = "cheat".equals(mode);
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port);
                BufferedWriter writer = new BufferedWriter(
                        new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8))) {
            String session = "live-fixture-" + label.toLowerCase(java.util.Locale.ROOT);
            write(writer, "HELLO|" + player + "|" + session + "|" + label);
            if (cheat) {
                String execution = loadExecutableFixture(fixtureJar);
                String metadata = Files.readString(fixtureMetadataPath(fixtureJar), StandardCharsets.UTF_8);
                if (!metadata.contains("\"id\":\"mcace-test-cheat\"")
                        || !metadata.contains("\"version\":\"" + versionFromLabel(label) + "\"")) {
                    throw new IOException("controlled cheat fixture metadata mismatch");
                }
                write(writer, "MOD|mcace-test-cheat|" + versionFromLabel(label) + "|"
                        + sha256(fixtureJar) + "|" + execution);
                // The server-side detector sees only movement deltas; it never trusts the client
                // to self-report a cheat signal.
                write(writer, "MOVE|1|0.5");
                write(writer, "MOVE|2|4.5");
                write(writer, "MOVE|3|4.5");
            } else {
                write(writer, "MOVE|1|0.5");
                write(writer, "MOVE|2|0.5");
                write(writer, "MOVE|3|0.5");
            }
            write(writer, "END");
        }
    }

    private static String loadExecutableFixture(Path fixtureJar) throws Exception {
        URL jarUrl = fixtureJar.toUri().toURL();
        try (URLClassLoader loader = new URLClassLoader(new URL[] {jarUrl}, null)) {
            Class<?> entrypoint = Class.forName(
                    "com.ellan.mcace.runtime.ControlledCheatEntrypoint", true, loader);
            URL source = entrypoint.getProtectionDomain().getCodeSource().getLocation();
            if (!source.toURI().equals(jarUrl.toURI())) {
                throw new IOException("controlled cheat entrypoint was not loaded from fixture JAR");
            }
            Object result = entrypoint.getMethod("execute").invoke(null);
            return String.valueOf(result);
        }
    }

    private static Path fixtureMetadataPath(Path fixtureJar) throws IOException {
        Path extracted = Files.createTempFile("mcace-cheat-fixture-metadata-", ".json");
        try (java.util.zip.ZipFile archive = new java.util.zip.ZipFile(fixtureJar.toFile());
                InputStream input = archive.getInputStream(archive.getEntry("fabric.mod.json"))) {
            Files.write(extracted, input.readAllBytes());
        }
        extracted.toFile().deleteOnExit();
        return extracted;
    }

    private static SignedDispositionPolicyDocument signedPolicy(KeyPair identity, String sha256)
            throws Exception {
        Instant now = Instant.now();
        DetectionRule rule = DetectionRule.newBuilder()
                .setRuleId("controlled-cheat-fixture-quarantine")
                .setRevision(1)
                .setPriority(100)
                .setSelector(DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256)
                        .setSha256(ByteString.copyFrom(HexFormat.of().parseHex(sha256))))
                .setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_CONFIRMED)
                .setDefaultAction(com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_QUARANTINE)
                .setIntroducedAtEpochMs(now.minusSeconds(1).toEpochMilli())
                .setEffectiveFromEpochMs(now.minusSeconds(1).toEpochMilli())
                .setExpiresAtEpochMs(now.plus(Duration.ofMinutes(5)).toEpochMilli())
                .build();
        DispositionPolicyDocument document = DispositionPolicyDocument.newBuilder()
                .setSchemaVersion(1)
                .setPolicyId("controlled-cheat-fixture")
                .setVersion("controlled-cheat-fixture-1")
                .setSequence(1)
                .setIssuedAtEpochMs(now.minusSeconds(2).toEpochMilli())
                .setEffectiveFromEpochMs(now.minusSeconds(1).toEpochMilli())
                .setExpiresAtEpochMs(now.plus(Duration.ofMinutes(5)).toEpochMilli())
                .setRolloutStage("FULL")
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(identity.getPublic())))
                .addRules(rule)
                .build();
        return DispositionPolicyDocuments.sign(document, identity.getPrivate(), identity.getPublic());
    }

    private static String[] split(String line, int expected, String type) throws IOException {
        String[] fields = line.split("\\|", -1);
        if (fields.length != expected || !type.equals(fields[0])) {
            throw new IOException("malformed " + type + " frame");
        }
        return fields;
    }

    private static void write(BufferedWriter writer, String line) throws IOException {
        writer.write(line);
        writer.newLine();
        writer.flush();
    }

    private static String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }

    private static String versionFromLabel(String label) {
        return label.substring("CHEAT_".length()).replace('_', '.');
    }

    private static String sanitize(String message) {
        return message == null ? "none" : message.replace('|', '_').replace('\n', ' ');
    }
}
