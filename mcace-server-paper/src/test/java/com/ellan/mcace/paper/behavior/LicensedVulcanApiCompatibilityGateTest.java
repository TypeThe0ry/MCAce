package com.ellan.mcace.paper.behavior;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

final class LicensedVulcanApiCompatibilityGateTest {
    private static final int MAX_PLUGIN_METADATA_BYTES = 64 * 1024;

    @Test
    @Timeout(60)
    @EnabledIfSystemProperty(named = "mcace.vulcan.compatibility.enabled", matches = "true")
    void validatesExplicitlySuppliedLicensedArtifactWithoutCopyingIt() throws Exception {
        Path artifact = Path.of(requiredProperty("mcace.vulcan.compatibility.jar"))
                .toAbsolutePath().normalize();
        Path reportPath = Path.of(requiredProperty("mcace.vulcan.compatibility.report"))
                .toAbsolutePath().normalize();
        GateReport report;
        try {
            report = inspect(artifact);
        } catch (GateFailure failure) {
            report = GateReport.failure(failure.stage());
        } catch (IOException exception) {
            report = GateReport.failure("ARTIFACT_UNREADABLE");
        } catch (ReflectiveOperationException | LinkageError exception) {
            report = GateReport.failure("EVENT_API_INCOMPATIBLE");
        }
        Files.createDirectories(reportPath.getParent());
        Files.writeString(reportPath, report.toJson(), StandardCharsets.UTF_8);
        assertTrue(report.passed(), report.toJson());
    }

    @Test
    void rejectsMetadataOnlyArtifactInsteadOfUsingTheSyntheticParentFixture(
            @TempDir Path temporaryDirectory) throws Exception {
        ClassLoader parent = LicensedVulcanApiCompatibilityGateTest.class.getClassLoader();
        Class<?> parentFixture = Class.forName(
                "me.frep.vulcan.api.event.VulcanFlagEvent", false, parent);
        assertEquals(parent, parentFixture.getClassLoader());

        Path artifact = temporaryDirectory.resolve("Vulcan.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(artifact))) {
            output.putNextEntry(new JarEntry("plugin.yml"));
            output.write("name: Vulcan\nversion: metadata-only\n".getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
        }

        assertThrows(ClassNotFoundException.class, () -> inspect(artifact));
    }

    private static GateReport inspect(Path artifact)
            throws IOException, ReflectiveOperationException, GateFailure {
        if (!Files.isRegularFile(artifact) || Files.isSymbolicLink(artifact)
                || !artifact.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar")) {
            throw new GateFailure("ARTIFACT_INVALID");
        }
        long size = Files.size(artifact);
        if (size <= 0L) {
            throw new GateFailure("ARTIFACT_INVALID");
        }
        PluginMetadata metadata = readMetadata(artifact);
        if (!"vulcan".equalsIgnoreCase(metadata.name())) {
            throw new GateFailure("PLUGIN_METADATA_MISMATCH");
        }
        VulcanApiCompatibility.Contract contract;
        URL artifactUrl = artifact.toUri().toURL();
        try (ChildFirstVulcanLoader loader = new ChildFirstVulcanLoader(
                artifactUrl, LicensedVulcanApiCompatibilityGateTest.class.getClassLoader())) {
            contract = VulcanApiCompatibility.inspect(loader);
        }
        return GateReport.success(
                sha256(artifact), size, metadata,
                contract.eventClass().getName(), contract.playerAccessor(), contract.checkAccessor(),
                contract.checkNameAccessor(), contract.stableCheckAccessor(),
                contract.eventViolationAccessor(), contract.checkViolationAccessor());
    }

    private static PluginMetadata readMetadata(Path artifact) throws IOException, GateFailure {
        try (JarFile jar = new JarFile(artifact.toFile())) {
            JarEntry entry = jar.getJarEntry("plugin.yml");
            if (entry == null) {
                entry = jar.getJarEntry("paper-plugin.yml");
            }
            if (entry == null || entry.getSize() > MAX_PLUGIN_METADATA_BYTES) {
                throw new GateFailure("PLUGIN_METADATA_MISSING");
            }
            byte[] encoded;
            try (InputStream input = jar.getInputStream(entry)) {
                encoded = input.readNBytes(MAX_PLUGIN_METADATA_BYTES + 1);
            }
            if (encoded.length > MAX_PLUGIN_METADATA_BYTES) {
                throw new GateFailure("PLUGIN_METADATA_OVERSIZED");
            }
            String name = "";
            String version = "";
            for (String line : new String(encoded, StandardCharsets.UTF_8).split("\\R")) {
                int separator = line.indexOf(':');
                if (separator <= 0) {
                    continue;
                }
                String key = line.substring(0, separator).strip().toLowerCase(Locale.ROOT);
                String value = unquote(line.substring(separator + 1).strip());
                if ("name".equals(key)) {
                    name = bounded(value, 64);
                } else if ("version".equals(key)) {
                    version = bounded(value, 64);
                }
            }
            if (name.isBlank() || version.isBlank()) {
                throw new GateFailure("PLUGIN_METADATA_INVALID");
            }
            return new PluginMetadata(name, version);
        }
    }

    private static String unquote(String value) {
        if (value.length() >= 2) {
            char first = value.charAt(0);
            char last = value.charAt(value.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return value.substring(1, value.length() - 1).strip();
            }
        }
        return value;
    }

    private static String bounded(String value, int maximum) throws GateFailure {
        if (value.isBlank() || value.length() > maximum || value.chars().anyMatch(Character::isISOControl)) {
            throw new GateFailure("PLUGIN_METADATA_INVALID");
        }
        return value;
    }

    private static String sha256(Path artifact) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(artifact)) {
                byte[] buffer = new byte[16 * 1024];
                for (int read; (read = input.read(buffer)) >= 0;) {
                    if (read > 0) {
                        digest.update(buffer, 0, read);
                    }
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String requiredProperty(String name) throws GateFailure {
        String value = System.getProperty(name, "").strip();
        if (value.isEmpty()) {
            throw new GateFailure("GATE_CONFIGURATION_MISSING");
        }
        return value;
    }

    private static String json(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 8);
        escaped.append('"');
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            switch (current) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> escaped.append(current);
            }
        }
        return escaped.append('"').toString();
    }

    private record PluginMetadata(String name, String version) {
        private PluginMetadata {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(version, "version");
        }
    }

    private static final class GateFailure extends Exception {
        @Serial
        private static final long serialVersionUID = 1L;
        private final String stage;

        private GateFailure(String stage) {
            super(stage);
            this.stage = Objects.requireNonNull(stage, "stage");
        }

        private String stage() {
            return stage;
        }
    }

    private record GateReport(
            String failureStage,
            String artifactSha256,
            long artifactSize,
            String pluginName,
            String pluginVersion,
            String eventType,
            String playerAccessor,
            String checkAccessor,
            String checkNameAccessor,
            String stableCheckAccessor,
            String eventViolationAccessor,
            String checkViolationAccessor,
            boolean passed) {
        private static GateReport success(
                String artifactSha256,
                long artifactSize,
                PluginMetadata metadata,
                String eventType,
                String playerAccessor,
                String checkAccessor,
                String checkNameAccessor,
                String stableCheckAccessor,
                String eventViolationAccessor,
                String checkViolationAccessor) {
            return new GateReport(
                    "NONE", artifactSha256, artifactSize, metadata.name(), metadata.version(), eventType,
                    playerAccessor, checkAccessor, checkNameAccessor, stableCheckAccessor,
                    eventViolationAccessor, checkViolationAccessor, true);
        }

        private static GateReport failure(String stage) {
            return new GateReport(
                    stage, "", 0L, "", "", "", "", "", "", "", "", "", false);
        }

        private String toJson() {
            return "{\n"
                    + "  \"schema\": \"VULCAN_LICENSED_API_COMPATIBILITY\",\n"
                    + "  \"generated_at\": " + json(Instant.now().toString()) + ",\n"
                    + "  \"failure_stage\": " + json(failureStage) + ",\n"
                    + "  \"artifact_sha256\": " + json(artifactSha256) + ",\n"
                    + "  \"artifact_size\": " + artifactSize + ",\n"
                    + "  \"plugin_name\": " + json(pluginName) + ",\n"
                    + "  \"plugin_version\": " + json(pluginVersion) + ",\n"
                    + "  \"event_type\": " + json(eventType) + ",\n"
                    + "  \"player_accessor\": " + json(playerAccessor) + ",\n"
                    + "  \"check_accessor\": " + json(checkAccessor) + ",\n"
                    + "  \"check_name_accessor\": " + json(checkNameAccessor) + ",\n"
                    + "  \"stable_check_accessor\": " + json(stableCheckAccessor) + ",\n"
                    + "  \"event_violation_accessor\": " + json(eventViolationAccessor) + ",\n"
                    + "  \"check_violation_accessor\": " + json(checkViolationAccessor) + ",\n"
                    + "  \"artifact_path_recorded\": false,\n"
                    + "  \"artifact_copied_or_redistributed\": false,\n"
                    + "  \"paper_process_coverage\": false,\n"
                    + "  \"licensed_plugin_enablement_coverage\": false,\n"
                    + "  \"real_behavior_event_delivery_coverage\": false,\n"
                    + "  \"limitations\": [\"STRUCTURAL_PREFLIGHT_ONLY\"],\n"
                    + "  \"passed\": " + passed + "\n"
                    + "}\n";
        }
    }

    private static final class ChildFirstVulcanLoader extends URLClassLoader {
        private ChildFirstVulcanLoader(URL artifact, ClassLoader parent) {
            super(new URL[] {artifact}, parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null && name.startsWith("me.frep.vulcan.")) {
                    // Every Vulcan-owned class must originate in the explicitly supplied artifact.
                    // Parent fallback is reserved for shared dependencies such as Bukkit/JDK APIs;
                    // otherwise the test-only structural fixture could make an API-less JAR pass.
                    loaded = findClass(name);
                }
                if (loaded == null) {
                    loaded = super.loadClass(name, false);
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        }
    }
}
