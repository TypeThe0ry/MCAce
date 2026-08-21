package com.ellan.mcace.core.authority;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Immutable exact-backend registry. An empty registry disables the authority protocol. */
public final class BackendAuthorityRegistry {
    private final Map<String, BackendAuthorityPin> pins;

    public BackendAuthorityRegistry(Map<String, BackendAuthorityPin> pins) {
        Objects.requireNonNull(pins, "pins");
        LinkedHashMap<String, BackendAuthorityPin> copy = new LinkedHashMap<>();
        pins.forEach((backend, pin) -> {
            Objects.requireNonNull(pin, "pin");
            if (!BackendAuthorityPin.bounded(backend, "registeredBackend").equals(pin.registeredBackend())) {
                throw new IllegalArgumentException("backend registry key does not match its pin");
            }
            if (copy.put(backend, pin) != null) {
                throw new IllegalArgumentException("duplicate backend authority pin");
            }
        });
        this.pins = Map.copyOf(copy);
    }

    public static BackendAuthorityRegistry disabled() {
        return new BackendAuthorityRegistry(Map.of());
    }

    public boolean enabled() {
        return !pins.isEmpty();
    }

    public Optional<BackendAuthorityPin> pinForRegisteredBackend(String registeredBackend) {
        return Optional.ofNullable(pins.get(registeredBackend));
    }

    public int size() {
        return pins.size();
    }
}
