package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class VelocityInventoryAdmissionConfigTest {
    @TempDir Path directory;

    @Test
    void absentAndLegacyFilesStayDisabledAndExplicitConfigurationLoads() throws Exception {
        Path path = directory.resolve("inventory-admission.properties");
        assertFalse(VelocityInventoryAdmissionConfig.load(path).enabled());
        assertFalse(Files.exists(path));
        Files.writeString(path, "denied-mod-ids=blocked_mod\n");
        assertFalse(VelocityInventoryAdmissionConfig.load(path).enabled());
        Files.writeString(path, "enabled=true\ndenied-mod-ids=blocked_mod\ndenied-selected-resource-packs=file/blocked.zip\n");
        var policy = VelocityInventoryAdmissionConfig.load(path);
        assertTrue(policy.enabled());
        assertTrue(policy.deniedModIds().contains("blocked_mod"));
        assertTrue(policy.deniedSelectedResourcePacks().contains("file/blocked.zip"));
    }

    @Test
    void rejectsInvalidBooleanEmptyItemDuplicateAndOversizedInput() throws Exception {
        Path path = directory.resolve("inventory-admission.properties");
        for (String text : new String[] {"enabled=maybe", "denied-mod-ids=a,", "denied-mod-ids=a,a",
                "denied-mod-ids=" + "a".repeat(257), "#".repeat(131073)}) {
            Files.writeString(path, text);
            assertThrows(java.io.IOException.class, () -> VelocityInventoryAdmissionConfig.load(path));
        }
    }
}
