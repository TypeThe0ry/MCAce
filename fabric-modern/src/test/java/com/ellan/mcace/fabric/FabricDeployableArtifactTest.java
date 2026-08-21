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
    private static final String MCACE_CLASS_PREFIX = "com/ellan/mcace/";
    private static final String PROTOBUF_CLASS_PREFIX = "com/google/protobuf/";
    private static final int JAVA_25_CLASS_MAJOR_VERSION = 69;
    private static final Pattern NESTED_JARS_ARRAY = Pattern.compile(
            "\\\"jars\\\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL);
    private static final Pattern NESTED_JAR_FILE = Pattern.compile(
            "\\\"file\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

    @TempDir
    Path temporaryDirectory;

    @Test
    void finalTargetJarCarriesAClosedJava25ProductionRuntime() throws Exception {
        ModernFabricTestTarget.Target target = ModernFabricTestTarget.current();
        Path artifact = ModernFabricTestTarget.deployableJar(target);
        Map<String, byte[]> classes = new HashMap<>();
        List<URL> runtimeUrls = new ArrayList<>();
        runtimeUrls.add(artifact.toUri().toURL());

        String metadata;
        Set<String> outerClassNames;
        Set<String> nestedNames = new TreeSet<>();
        Set<String> loaderModIds = new TreeSet<>();
        try (JarFile outer = new JarFile(artifact.toFile())) {
            JarEntry metadataEntry = outer.getJarEntry("fabric.mod.json");
            assertNotNull(metadataEntry, "final remap JAR is missing fabric.mod.json");
            metadata = new String(outer.getInputStream(metadataEntry).readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(loaderModIds.add(ModernFabricTestTarget.jsonString(metadata, "id")));
            readClasses(outer, classes);
            outerClassNames = Set.copyOf(classes.keySet());
            Set<String> declaredNestedNames = declaredNestedJarFiles(metadata);

            var entries = outer.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().startsWith("META-INF/jars/")
                        || !entry.getName().endsWith(".jar")) {
                    continue;
                }
                nestedNames.add(entry.getName());
                assertTrue(declaredNestedNames.contains(entry.getName()),
                        "final artifact carries an undeclared nested JAR: " + entry.getName());
                byte[] bytes = outer.getInputStream(entry).readAllBytes();
                String nestedMetadata = nestedFabricMetadata(bytes);
                assertNotNull(nestedMetadata,
                        "Fabric Loader cannot discover nested JAR without root fabric.mod.json: "
                                + entry.getName());
                String nestedModId = ModernFabricTestTarget.jsonString(nestedMetadata, "id");
                assertTrue(loaderModIds.add(nestedModId),
                        "duplicate outer/nested Fabric mod id " + nestedModId);
                readClasses(bytes, classes);
                Path extracted = temporaryDirectory.resolve(Path.of(entry.getName()).getFileName().toString());
                Files.write(extracted, bytes);
                runtimeUrls.add(extracted.toUri().toURL());
            }
            assertEquals(declaredNestedNames, nestedNames,
                    "fabric.mod.json jars must exactly match the packaged Loader-discoverable nested JARs");
        }

        assertEquals(target.minecraftVersion(), ModernFabricTestTarget.jsonString(metadata, "minecraft"));
        assertEquals(target.fabricApiVersion(), ModernFabricTestTarget.jsonString(metadata, "fabric-api"));
        assertEquals(">=25", ModernFabricTestTarget.jsonString(metadata, "java"));
        assertEquals(target.buildId(),
                ModernFabricTestTarget.jsonString(metadata, "mcace:client_build_id"));
        assertEquals("mcace", ModernFabricTestTarget.jsonString(metadata, "id"));
        assertFalse(metadata.contains("${"), metadata);
        assertFalse(metadata.contains("\"minecraft\": \"~"), metadata);
        assertFalse(metadata.contains("\"fabric-api\": \"*\""), metadata);

        assertEquals(Set.of(
                "META-INF/jars/protobuf-java-4.32.1.jar"), nestedNames,
                "final modern Fabric JAR must carry only Loom's Loader-discoverable protobuf include");
        assertFalse(nestedNames.stream().anyMatch(name -> name.contains("protobuf-java-util")), nestedNames::toString);
        assertFalse(nestedNames.stream().anyMatch(name -> name.contains("gson")), nestedNames::toString);
        assertFalse(nestedNames.stream().anyMatch(name -> name.contains("guava")), nestedNames::toString);

        assertTrue(outerClassNames.contains("com/ellan/mcace/fabric/MCAceFabricClient"));
        assertTrue(outerClassNames.contains("com/ellan/mcace/client/observation/ArtifactObservationCollector"));
        assertTrue(outerClassNames.contains("com/ellan/mcace/core/disposition/ArtifactObservation"));
        assertTrue(outerClassNames.contains("com/ellan/mcace/sdk/MCAceApi"));
        assertTrue(outerClassNames.contains("com/ellan/mcace/protocol/ProtocolConstants"));
        assertTrue(classes.containsKey("com/google/protobuf/Message"));

        byte[] entrypoint = classes.get("com/ellan/mcace/fabric/MCAceFabricClient");
        assertTrue(classMajorVersion(entrypoint) >= JAVA_25_CLASS_MAJOR_VERSION,
                "modern Fabric entrypoint must be compiled for Java 25 or newer");
        assertOfficialMinecraftNames(classes);

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

    private static Set<String> declaredNestedJarFiles(String metadata) {
        Matcher jars = NESTED_JARS_ARRAY.matcher(metadata);
        assertTrue(jars.find(), "processed fabric.mod.json is missing Loom's jars array");
        String jarsBody = jars.group(1);
        assertFalse(jars.find(), "processed fabric.mod.json has duplicate jars arrays");
        Matcher files = NESTED_JAR_FILE.matcher(jarsBody);
        Set<String> declared = new TreeSet<>();
        while (files.find()) {
            String path = files.group(1);
            assertTrue(path.startsWith("META-INF/jars/") && path.endsWith(".jar")
                            && !path.contains("..") && path.indexOf('\\') < 0,
                    "invalid nested Fabric JAR path: " + path);
            assertTrue(declared.add(path), "duplicate nested Fabric JAR declaration: " + path);
        }
        assertFalse(declared.isEmpty(), "processed fabric.mod.json has an empty jars array");
        return Set.copyOf(declared);
    }

    private static String nestedFabricMetadata(byte[] jarBytes) throws IOException {
        try (JarInputStream jar = new JarInputStream(new ByteArrayInputStream(jarBytes))) {
            JarEntry entry;
            while ((entry = jar.getNextJarEntry()) != null) {
                if (!entry.isDirectory() && entry.getName().equals("fabric.mod.json")) {
                    return new String(jar.readAllBytes(), StandardCharsets.UTF_8);
                }
            }
        }
        return null;
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

    private static int classMajorVersion(byte[] classBytes) throws IOException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(classBytes))) {
            assertEquals(0xCAFEBABE, input.readInt(), "invalid class-file magic");
            input.readUnsignedShort();
            return input.readUnsignedShort();
        }
    }

    private static void assertOfficialMinecraftNames(Map<String, byte[]> classes) {
        StringBuilder fabricConstants = new StringBuilder();
        classes.forEach((name, bytes) -> {
            if (name.startsWith("com/ellan/mcace/fabric/")) {
                fabricConstants.append(new String(bytes, StandardCharsets.ISO_8859_1));
            }
        });
        String constants = fabricConstants.toString();
        assertTrue(constants.contains("net/minecraft/client/Minecraft"),
                "modern artifact does not link the official Minecraft client name");
        assertTrue(constants.contains("net/minecraft/resources/Identifier"),
                "modern artifact does not link the official Identifier name");
        assertFalse(constants.contains("net/minecraft/client/MinecraftClient"),
                "modern artifact leaked a 1.21.11 Yarn MinecraftClient reference");
        assertFalse(constants.contains("net/minecraft/util/Identifier"),
                "modern artifact leaked a 1.21.11 Yarn Identifier reference");
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
