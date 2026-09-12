package com.ellan.mcace.core.session;

import com.ellan.mcace.protocol.generated.AuthRequest;
import java.util.Objects;
import java.util.Set;

/** Administrator-defined inventory compatibility requirements, not a cheating verdict. */
public record InventoryAdmissionPolicy(boolean enabled, Set<String> deniedModIds,
        Set<String> deniedSelectedResourcePacks) {
    public enum Finding { NONE, PROHIBITED_LOADED_MOD, PROHIBITED_SELECTED_RESOURCE_PACK }

    public InventoryAdmissionPolicy {
        deniedModIds = checked(deniedModIds);
        deniedSelectedResourcePacks = checked(deniedSelectedResourcePacks);
    }

    public static InventoryAdmissionPolicy disabled() {
        return new InventoryAdmissionPolicy(false, Set.of(), Set.of());
    }

    public Finding evaluate(AuthRequest request) {
        Objects.requireNonNull(request, "request");
        if (!enabled) return Finding.NONE;
        if (request.getLoadedModsList().stream().anyMatch(mod -> deniedModIds.contains(mod.getId()))) {
            return Finding.PROHIBITED_LOADED_MOD;
        }
        if (request.getSelectedResourcePacksList().stream().anyMatch(deniedSelectedResourcePacks::contains)) {
            return Finding.PROHIBITED_SELECTED_RESOURCE_PACK;
        }
        return Finding.NONE;
    }

    private static Set<String> checked(Set<String> values) {
        Objects.requireNonNull(values, "values");
        if (values.size() > 256) throw new IllegalArgumentException("too many inventory admission selectors");
        for (String value : values) {
            if (value == null || value.isBlank() || value.length() > 256
                    || !value.equals(value.trim()) || value.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("invalid inventory admission selector");
            }
        }
        return Set.copyOf(values);
    }
}
