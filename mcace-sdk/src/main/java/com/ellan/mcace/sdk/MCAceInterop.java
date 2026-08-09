package com.ellan.mcace.sdk;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/**
 * Reflection-only discovery for MCAce plugins that embed separate SDK copies in isolated class loaders.
 *
 * <p>A provider need expose only this public zero-argument method:</p>
 *
 * <pre>{@code
 * public Function<Map<String, Object>, Map<String, Object>> mcaceInteropV1() {
 *     return MCAceInteropExports.from(api);
 * }
 * }</pre>
 *
 * <p>The method boundary uses only JDK bootstrap types ({@link Function}, {@link Map}, {@link String},
 * {@link java.util.UUID}, boxed primitives, and lists). Consumers discover it by name rather than by an
 * {@code MCAceApi} class identity, then receive their own local read-only wrapper. This avoids the
 * class-loader identity problem caused by shaded server plugins. It is not a control plane and cannot
 * apply a punishment or retrieve raw evidence.</p>
 *
 * @since 1.0
 */
public final class MCAceInterop {
    /** Public method name providers expose for the version-one interop bridge. */
    public static final String PROVIDER_METHOD_V1 = "mcaceInteropV1";

    /** Request-map key identifying the interop operation. */
    public static final String OPERATION = "operation";
    /** Operation that reads version and capability metadata. */
    public static final String DESCRIPTOR_OPERATION = "descriptor";
    /** Operation that reads a player snapshot. */
    public static final String SNAPSHOT_OPERATION = "snapshot";
    /** Operation that reads active-session metadata. */
    public static final String SESSION_OPERATION = "session";
    /** Operation that reads content-free evidence metadata. */
    public static final String EVIDENCE_OPERATION = "evidence";
    /** Request-map key holding a {@link java.util.UUID} player identifier. */
    public static final String PLAYER_ID = "player_id";
    /** Response-map key containing {@value #STATUS_OK} or {@value #STATUS_NOT_FOUND}. */
    public static final String STATUS = "status";
    /** Successful response status. */
    public static final String STATUS_OK = "ok";
    /** Missing-player response status. */
    public static final String STATUS_NOT_FOUND = "not_found";
    /** Unsupported-operation response status. */
    public static final String STATUS_NOT_SUPPORTED = "not_supported";

    private MCAceInterop() {
    }

    /**
     * Discovers a provider's version-one bridge without requiring a shared MCAce class loader.
     *
     * @param candidate plugin instance or service object
     * @return bridge when the public provider method is present; empty when it is absent
     * @throws MCAceInteropException when a matching method exists but is malformed or fails to initialize
     */
    public static Optional<MCAceInteropBridge> discover(Object candidate) {
        Objects.requireNonNull(candidate, "candidate");
        Method method;
        try {
            method = candidate.getClass().getMethod(PROVIDER_METHOD_V1);
        } catch (NoSuchMethodException ignored) {
            return Optional.empty();
        }
        if (!Modifier.isPublic(method.getModifiers()) || method.getParameterCount() != 0) {
            throw new MCAceInteropException("invalid " + PROVIDER_METHOD_V1 + " method");
        }
        Object result;
        try {
            result = method.invoke(candidate);
        } catch (IllegalAccessException | InvocationTargetException exception) {
            throw new MCAceInteropException("unable to initialize MCAce interop provider", exception);
        }
        if (!(result instanceof Function<?, ?> function)) {
            throw new MCAceInteropException(PROVIDER_METHOD_V1 + " must return a java.util.function.Function");
        }
        return Optional.of(new MCAceInteropBridge(function));
    }
}
