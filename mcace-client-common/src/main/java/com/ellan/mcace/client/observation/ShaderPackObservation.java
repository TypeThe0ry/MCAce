package com.ellan.mcace.client.observation;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Reads the shader pack that is actually active in a client, when an optional
 * shader loader exposes that state.  MCAce intentionally has no hard Iris
 * dependency: a client without a compatible shader loader reports an empty
 * list instead of failing authentication.
 *
 * <p>The returned value is an observation only.  It is sent alongside the
 * signed client report and must not be treated as proof that a client is
 * cheat-free or as a standalone punishment signal.</p>
 */
public final class ShaderPackObservation {
    private static final List<String> IRIS_ENTRYPOINTS = List.of(
            "net.irisshaders.iris.Iris",
            "net.coderbot.iris.Iris");
    private static final String IRIS_API = "net.irisshaders.iris.api.v0.IrisApi";

    private ShaderPackObservation() {
    }

    /**
     * Returns at most one normalized, non-sentinel shader-pack identifier.
     * This method is safe when Iris (or any other shader loader) is absent.
     */
    public static List<String> currentEnabledShaderPackIds() {
        ClassLoader contextLoader = Thread.currentThread().getContextClassLoader();
        ClassLoader ownLoader = ShaderPackObservation.class.getClassLoader();
        List<ClassLoader> loaders = new ArrayList<>(2);
        if (contextLoader != null) loaders.add(contextLoader);
        if (ownLoader != null && ownLoader != contextLoader) loaders.add(ownLoader);
        for (ClassLoader loader : loaders) {
            if (loader == null) continue;
            String name = readIrisPackName(loader);
            if (name != null) {
                return List.of(name);
            }
        }
        return List.of();
    }

    /**
     * Normalizes provider values for deterministic protocol encoding and tests.
     */
    static List<String> normalizePackNames(Collection<?> values) {
        return values.stream()
                .map(ShaderPackObservation::stringValue)
                .map(ShaderPackObservation::normalizePackName)
                .flatMap(Optional::stream)
                .distinct()
                .sorted(Comparator.naturalOrder())
                .toList();
    }

    private static String readIrisPackName(ClassLoader loader) {
        for (String entrypoint : IRIS_ENTRYPOINTS) {
            try {
                Class<?> iris = Class.forName(entrypoint, false, loader);
                Boolean inUse = readApiInUse(loader);
                if (Boolean.FALSE.equals(inUse)) {
                    return null;
                }
                String current = normalizePackName(invokeStatic(iris, "getCurrentPackName"))
                        .orElseGet(() -> readPackNameFromConfig(iris));
                if (current != null) {
                    return current;
                }
                // A known provider was found, but it has no usable current pack.
                // Do not continue with another class loader and accidentally read
                // a stale duplicate provider from a development classpath.
                return null;
            } catch (ClassNotFoundException ignored) {
                // Optional provider is not installed in this client.
            } catch (LinkageError | RuntimeException ignored) {
                // A provider that is present but not initialized must not break
                // the MCAce handshake.  The next provider/classloader may still work.
            }
        }
        return null;
    }

    private static Boolean readApiInUse(ClassLoader loader) {
        try {
            Class<?> api = Class.forName(IRIS_API, false, loader);
            Object instance = invokeStatic(api, "getInstance");
            Object result = invoke(instance, "isShaderPackInUse");
            return result instanceof Boolean value ? value : null;
        } catch (ClassNotFoundException ignored) {
            return null;
        } catch (LinkageError | RuntimeException ignored) {
            return null;
        }
    }

    private static String readPackNameFromConfig(Class<?> iris) {
        Object config = invokeStatic(iris, "getIrisConfig");
        if (config == null) {
            return null;
        }
        Object configured = invoke(config, "getShaderPackName");
        return normalizePackName(configured).orElse(null);
    }

    private static Object invokeStatic(Class<?> type, String methodName) {
        try {
            Method method = type.getMethod(methodName);
            return method.invoke(null);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ignored) {
            return null;
        }
    }

    private static Object invoke(Object receiver, String methodName) {
        if (receiver == null) {
            return null;
        }
        try {
            Method method = receiver.getClass().getMethod(methodName);
            return method.invoke(receiver);
        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ignored) {
            return null;
        }
    }

    private static String stringValue(Object value) {
        if (value instanceof Optional<?> optional) {
            return optional.map(ShaderPackObservation::stringValue).orElse(null);
        }
        return value == null ? null : value.toString();
    }

    private static Optional<String> normalizePackName(Object value) {
        String raw = stringValue(value);
        if (raw == null) {
            return Optional.empty();
        }
        String normalized = raw.strip();
        if (normalized.isEmpty()) {
            return Optional.empty();
        }
        String sentinel = normalized.toLowerCase(Locale.ROOT);
        if (sentinel.equals("(off)") || sentinel.equals("off") || sentinel.equals("none")
                || sentinel.equals("null") || sentinel.equals("disabled")) {
            return Optional.empty();
        }
        return Optional.of(normalized);
    }
}
