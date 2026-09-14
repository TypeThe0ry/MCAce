package com.ellan.mcace.core.session;

import static org.junit.jupiter.api.Assertions.*;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.LoadedModEntry;
import com.ellan.mcace.protocol.generated.ModEntry;
import java.util.Set;
import org.junit.jupiter.api.Test;

final class InventoryAdmissionPolicyTest {
    @Test
    void explicitEnabledPolicyMatchesLoadedModsAndSelectedPacksOnly() {
        var policy = new InventoryAdmissionPolicy(true, Set.of("blocked_mod"), Set.of("file/blocked.zip"));
        var mod = AuthRequest.newBuilder().addLoadedMods(LoadedModEntry.newBuilder().setId("blocked_mod")).build();
        assertEquals(InventoryAdmissionPolicy.Finding.PROHIBITED_LOADED_MOD, policy.evaluate(mod));
        assertEquals(InventoryAdmissionPolicy.Finding.NONE, InventoryAdmissionPolicy.disabled().evaluate(mod));
        assertEquals(InventoryAdmissionPolicy.Finding.NONE, policy.evaluate(AuthRequest.newBuilder()
                .addMods(ModEntry.newBuilder().setId("blocked_mod")).build()));
        assertEquals(InventoryAdmissionPolicy.Finding.PROHIBITED_SELECTED_RESOURCE_PACK,
                policy.evaluate(AuthRequest.newBuilder().addSelectedResourcePacks("file/blocked.zip").build()));
        assertEquals(InventoryAdmissionPolicy.Finding.NONE,
                policy.evaluate(AuthRequest.newBuilder().addSelectedResourcePacks("file/other.zip").build()));
        assertEquals(InventoryAdmissionPolicy.Finding.NONE, policy.evaluate(AuthRequest.getDefaultInstance()));
    }

    @Test
    void selectorsAreBoundedImmutableAndExact() {
        var ids = new java.util.HashSet<>(Set.of("blocked_mod"));
        var policy = new InventoryAdmissionPolicy(true, ids, Set.of());
        ids.clear();
        assertEquals(Set.of("blocked_mod"), policy.deniedModIds());
        assertThrows(IllegalArgumentException.class, () -> new InventoryAdmissionPolicy(true, Set.of(" "), Set.of()));
        assertThrows(IllegalArgumentException.class, () -> new InventoryAdmissionPolicy(true, Set.of("a\nb"), Set.of()));
        assertThrows(IllegalArgumentException.class, () -> new InventoryAdmissionPolicy(true, Set.of("x".repeat(257)), Set.of()));
        assertEquals(InventoryAdmissionPolicy.Finding.NONE, policy.evaluate(AuthRequest.newBuilder()
                .addLoadedMods(LoadedModEntry.newBuilder().setId("BLOCKED_MOD")).build()));
    }
}
