package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FabricDeployableArtifactTest {
    private static final String DEPLOYABLE_JAR_PROPERTY = "mcace.fabric.deployable-jar";
    private static final String BUILD_ID_PROPERTY = "mcace.fabric.client-build-id";
    private static final String MCACE_CLASS_PREFIX = "com/ellan/mcace/";
    private static final String CORE_CLASS_PREFIX = "com/ellan/mcace/core/";
    private static final String PROTOBUF_CLASS_PREFIX = "com/google/protobuf/";
    private static final Set<String> CLIENT_SAFE_CORE_CLASSES = Set.of(
            "com/ellan/mcace/core/disposition/ArtifactObservation",
            "com/ellan/mcace/core/disposition/ArtifactType",
            "com/ellan/mcace/core/disposition/Confidence",
            "com/ellan/mcace/core/disposition/ObservationOrigin");

    @TempDir
    Path temporaryDirectory;

    @Test
    void finalRemapJarCarriesAClosedProductionRuntime() throws Exception {
        Path artifact = deployableJar();
        Map<String, byte[]> classes = new HashMap<>();
        List<URL> runtimeUrls = new ArrayList<>();
        runtimeUrls.add(artifact.toUri().toURL());

        String metadata;
        Set<String> nestedNames = new TreeSet<>();
        try (JarFile outer = new JarFile(artifact.toFile())) {
            JarEntry metadataEntry = outer.getJarEntry("fabric.mod.json");
            assertNotNull(metadataEntry, "final remap JAR is missing fabric.mod.json");
            metadata = new String(outer.getInputStream(metadataEntry).readAllBytes(), StandardCharsets.UTF_8);
            readClasses(outer, classes);

            var entries = outer.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().startsWith("META-INF/jars/")
                        || !entry.getName().endsWith(".jar")) {
                    continue;
                }
                nestedNames.add(entry.getName());
                byte[] bytes = outer.getInputStream(entry).readAllBytes();
                readClasses(bytes, classes);
                Path extracted = temporaryDirectory.resolve(Path.of(entry.getName()).getFileName().toString());
                Files.write(extracted, bytes);
                runtimeUrls.add(extracted.toUri().toURL());
            }
        }

        assertTrue(metadata.contains("\"minecraft\": \"1.21.11\""), metadata);
        assertEquals(">=0.19.3", jsonStringProperty(metadata, "fabricloader"));
        assertTrue(metadata.contains("\"fabric-api\": \"0.141.6+1.21.11\""), metadata);
        String expectedBuildId = System.getProperty(BUILD_ID_PROPERTY, "").strip();
        assertFalse(expectedBuildId.isEmpty(), BUILD_ID_PROPERTY + " was not configured by Gradle");
        assertTrue(
                metadata.contains("\"mcace:client_build_id\": \"" + expectedBuildId + "\""),
                metadata);
        assertFalse(metadata.contains("\"minecraft\": \"~"), metadata);
        assertFalse(metadata.contains("\"fabric-api\": \"*\""), metadata);

        assertNestedLibrary(nestedNames, "mcace-client-common-");
        assertNestedLibrary(nestedNames, "mcace-core-");
        assertTrue(nestedNames.stream()
                        .map(name -> Path.of(name).getFileName().toString())
                        .anyMatch(name -> name.startsWith("mcace-core-")
                                && name.endsWith("-client-safe.jar")),
                () -> "final Fabric artifact is missing the reviewed client-safe core JAR: "
                        + nestedNames);
        assertNestedLibrary(nestedNames, "mcace-sdk-");
        assertNestedLibrary(nestedNames, "mcace-protocol-");
        assertNestedLibrary(nestedNames, "protobuf-java-4.32.1.jar");
        assertFalse(nestedNames.stream().anyMatch(name -> name.contains("protobuf-java-util")), nestedNames::toString);
        assertFalse(nestedNames.stream().anyMatch(name -> name.contains("gson")), nestedNames::toString);
        assertFalse(nestedNames.stream().anyMatch(name -> name.contains("guava")), nestedNames::toString);

        assertTrue(classes.containsKey("com/ellan/mcace/fabric/MCAceFabricClient"));
        assertTrue(classes.containsKey("com/ellan/mcace/client/observation/ArtifactObservationCollector"));
        assertTrue(classes.containsKey("com/ellan/mcace/core/disposition/ArtifactObservation"));
        assertTrue(classes.containsKey("com/ellan/mcace/sdk/MCAceApi"));
        assertTrue(classes.containsKey("com/ellan/mcace/protocol/ProtocolConstants"));
        assertTrue(classes.containsKey("com/google/protobuf/Message"));

        Set<String> packagedCoreClasses = new TreeSet<>();
        classes.keySet().stream()
                .filter(name -> name.startsWith(CORE_CLASS_PREFIX))
                .forEach(packagedCoreClasses::add);
        assertEquals(CLIENT_SAFE_CORE_CLASSES, packagedCoreClasses,
                "final Fabric artifact must carry exactly the reviewed client-safe core classes");

        Set<String> privacyViolations = new TreeSet<>();
        classes.forEach((className, classBytes) -> FabricPrivacyBytecodePolicy.violations(classBytes)
                .forEach(marker -> privacyViolations.add(className + " -> " + marker)));
        assertEquals(Set.of(), privacyViolations,
                "final remap JAR or one of its nested JARs links a forbidden privacy API");

        Set<String> unresolved = unresolvedProductionReferences(classes);
        assertEquals(Set.of(), unresolved, "final remap JAR has unresolved MCAce/Protobuf references");

        try (URLClassLoader isolated = new URLClassLoader(
                runtimeUrls.toArray(URL[]::new), ClassLoader.getPlatformClassLoader())) {
            Class<?> collector = Class.forName(
                    "com.ellan.mcace.client.observation.ArtifactObservationCollector", true, isolated);
            assertNotNull(collector.getDeclaredConstructor().newInstance());
        }
    }

    private static Path deployableJar() {
        String configured = System.getProperty(DEPLOYABLE_JAR_PROPERTY, "").trim();
        assertFalse(configured.isEmpty(), DEPLOYABLE_JAR_PROPERTY + " was not configured by Gradle");
        Path artifact = Path.of(configured).toAbsolutePath().normalize();
        assertTrue(Files.isRegularFile(artifact), "deployable Fabric JAR is missing: " + artifact);
        return artifact;
    }

    private static String jsonStringProperty(String json, String property) {
        Pattern pattern = Pattern.compile(
                "\\\"" + Pattern.quote(property) + "\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"");
        Matcher matcher = pattern.matcher(json);
        assertTrue(matcher.find(), () -> "missing JSON string property " + property);
        String encoded = matcher.group(1);
        assertFalse(matcher.find(), () -> "duplicate JSON string property " + property);
        return decodeJsonString(encoded);
    }

    private static String decodeJsonString(String encoded) {
        StringBuilder decoded = new StringBuilder(encoded.length());
        for (int index = 0; index < encoded.length(); index++) {
            char value = encoded.charAt(index);
            if (value != '\\') {
                decoded.append(value);
                continue;
            }
            assertTrue(++index < encoded.length(), "truncated JSON escape");
            char escape = encoded.charAt(index);
            switch (escape) {
                case '"', '\\', '/' -> decoded.append(escape);
                case 'b' -> decoded.append('\b');
                case 'f' -> decoded.append('\f');
                case 'n' -> decoded.append('\n');
                case 'r' -> decoded.append('\r');
                case 't' -> decoded.append('\t');
                case 'u' -> {
                    assertTrue(index + 4 < encoded.length(), "truncated JSON unicode escape");
                    decoded.append((char) Integer.parseInt(encoded.substring(index + 1, index + 5), 16));
                    index += 4;
                }
                default -> throw new IllegalArgumentException("invalid JSON escape: " + escape);
            }
        }
        return decoded.toString();
    }

    private static void assertNestedLibrary(Set<String> nestedNames, String filePrefix) {
        assertTrue(nestedNames.stream()
                        .map(name -> Path.of(name).getFileName().toString())
                        .anyMatch(name -> name.startsWith(filePrefix)),
                () -> "missing nested library " + filePrefix + " in " + nestedNames);
    }

    private static void readClasses(JarFile jar, Map<String, byte[]> classes) throws IOException {
        var entries = jar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
                putClass(classes, entry.getName(), jar.getInputStream(entry).readAllBytes());
            }
        }
    }

    private static void readClasses(byte[] jarBytes, Map<String, byte[]> classes) throws IOException {
        try (JarInputStream jar = new JarInputStream(new ByteArrayInputStream(jarBytes))) {
            JarEntry entry;
            while ((entry = jar.getNextJarEntry()) != null) {
                if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
                    putClass(classes, entry.getName(), jar.readAllBytes());
                }
            }
        }
    }

    private static void putClass(Map<String, byte[]> classes, String entryName, byte[] bytes) {
        String binaryName = entryName.substring(0, entryName.length() - ".class".length());
        byte[] previous = classes.putIfAbsent(binaryName, bytes);
        assertTrue(previous == null, "duplicate production class in final Fabric artifact: " + binaryName);
    }

    private static Set<String> unresolvedProductionReferences(Map<String, byte[]> classes) throws IOException {
        Set<String> unresolved = new TreeSet<>();
        for (Map.Entry<String, byte[]> packaged : classes.entrySet()) {
            if (!packaged.getKey().startsWith(MCACE_CLASS_PREFIX)) {
                continue;
            }
            for (String referenced : classReferences(packaged.getValue())) {
                if ((referenced.startsWith(MCACE_CLASS_PREFIX)
                                || referenced.startsWith(PROTOBUF_CLASS_PREFIX))
                        && !classes.containsKey(referenced)) {
                    unresolved.add(packaged.getKey() + " -> " + referenced);
                }
            }
        }
        return unresolved;
    }

    private static Set<String> classReferences(byte[] classBytes) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(classBytes))) {
            assertEquals(0xCAFEBABE, input.readInt(), "invalid class-file magic");
            input.readUnsignedShort();
            input.readUnsignedShort();
            int constantPoolCount = input.readUnsignedShort();
            Object[] constants = new Object[constantPoolCount];
            for (int index = 1; index < constantPoolCount; index++) {
                int tag = input.readUnsignedByte();
                switch (tag) {
                    case 1 -> constants[index] = input.readUTF();
                    case 3, 4 -> input.skipNBytes(4);
                    case 5, 6 -> {
                        input.skipNBytes(8);
                        index++;
                    }
                    case 7 -> constants[index] = input.readUnsignedShort();
                    case 8, 16, 19, 20 -> input.skipNBytes(2);
                    case 9, 10, 11, 12, 17, 18 -> input.skipNBytes(4);
                    case 15 -> input.skipNBytes(3);
                    default -> throw new IOException("unsupported class-file constant tag " + tag);
                }
            }

            Set<String> references = new HashSet<>();
            for (Object constant : constants) {
                if (!(constant instanceof Integer nameIndex)) {
                    continue;
                }
                Object className = constants[nameIndex];
                if (className instanceof String value) {
                    addClassName(references, value);
                }
            }
            return references;
        }
    }

    private static void addClassName(Set<String> references, String value) {
        if (!value.startsWith("[")) {
            references.add(value);
            return;
        }
        int cursor = 0;
        while ((cursor = value.indexOf('L', cursor)) >= 0) {
            int end = value.indexOf(';', cursor);
            if (end < 0) {
                return;
            }
            references.add(value.substring(cursor + 1, end));
            cursor = end + 1;
        }
    }
}
