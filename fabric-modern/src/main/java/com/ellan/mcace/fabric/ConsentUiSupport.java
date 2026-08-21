package com.ellan.mcace.fabric;

import com.mojang.blaze3d.pipeline.RenderTarget;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Objects;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.Gui;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.renderer.GameRenderer;

/** Safety, scrolling, and narrow cross-version access shared by visible consent screens. */
final class ConsentUiSupport {
    private static final Method GUI_SCREEN = publicMethod(Gui.class, "screen");
    private static final Method GUI_SET_SCREEN = publicMethod(Gui.class, "setScreen", Screen.class);
    private static final Field MINECRAFT_SCREEN = publicField(Minecraft.class, "screen");
    private static final Method MINECRAFT_SET_SCREEN = publicMethod(Minecraft.class, "setScreen", Screen.class);
    private static final Method MINECRAFT_MAIN_RENDER_TARGET =
            publicMethod(Minecraft.class, "getMainRenderTarget");
    private static final Method GAME_RENDERER_MAIN_RENDER_TARGET =
            publicMethod(GameRenderer.class, "mainRenderTarget");

    private ConsentUiSupport() { }

    /** 26.1 owns the active screen on Minecraft; 26.2 owns it on Gui. */
    static Screen currentScreen(Minecraft client) {
        Objects.requireNonNull(client, "client");
        if (GUI_SCREEN != null) {
            return (Screen) invoke(GUI_SCREEN, client.gui);
        }
        if (MINECRAFT_SCREEN != null) {
            try {
                return (Screen) MINECRAFT_SCREEN.get(client);
            } catch (IllegalAccessException exception) {
                throw incompatibleApi("cannot read Minecraft.screen", exception);
            }
        }
        throw incompatibleApi("no supported active-screen accessor", null);
    }

    /** 26.1 exposes Minecraft.setScreen; 26.2 exposes Gui.setScreen. */
    static void setScreen(Minecraft client, Screen screen) {
        Objects.requireNonNull(client, "client");
        if (GUI_SET_SCREEN != null) {
            invoke(GUI_SET_SCREEN, client.gui, screen);
            return;
        }
        if (MINECRAFT_SET_SCREEN != null) {
            invoke(MINECRAFT_SET_SCREEN, client, screen);
            return;
        }
        throw incompatibleApi("no supported set-screen accessor", null);
    }

    /** 26.2 moved the main target from Minecraft to GameRenderer. */
    static RenderTarget mainRenderTarget(Minecraft client) {
        Objects.requireNonNull(client, "client");
        if (GAME_RENDERER_MAIN_RENDER_TARGET != null) {
            return (RenderTarget) invoke(GAME_RENDERER_MAIN_RENDER_TARGET, client.gameRenderer);
        }
        if (MINECRAFT_MAIN_RENDER_TARGET != null) {
            return (RenderTarget) invoke(MINECRAFT_MAIN_RENDER_TARGET, client);
        }
        throw incompatibleApi("no supported main render-target accessor", null);
    }

    static String safeDisplay(String value) {
        StringBuilder sanitized = new StringBuilder(value.length());
        value.codePoints().forEach(codePoint -> {
            int type = Character.getType(codePoint);
            if (Character.isISOControl(codePoint)
                    || type == Character.FORMAT
                    || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR) {
                sanitized.append('\uFFFD');
            } else {
                sanitized.appendCodePoint(codePoint);
            }
        });
        return sanitized.toString();
    }

    static int contentHeight(int lineStep, int totalLines, int paragraphCount, int paragraphGap) {
        int safeLineStep = Math.max(1, lineStep);
        int safeLines = Math.max(1, totalLines);
        int safeParagraphs = Math.max(1, paragraphCount);
        return Math.addExact(Math.multiplyExact(safeLines, safeLineStep),
                Math.multiplyExact(Math.max(0, safeParagraphs - 1), Math.max(0, paragraphGap)));
    }

    static int maxScroll(int contentHeight, int viewportHeight) {
        return Math.max(0, contentHeight - Math.max(0, viewportHeight));
    }

    static int clampScroll(int offset, int maxScroll) {
        return Math.max(0, Math.min(offset, Math.max(0, maxScroll)));
    }

    static int wheelScroll(int offset, int maxScroll, double verticalAmount, int lineStep) {
        int delta = (int) Math.round(-verticalAmount * Math.max(1, lineStep) * 3.0d);
        if (delta == 0 && verticalAmount != 0.0d) {
            delta = verticalAmount > 0.0d ? -1 : 1;
        }
        return clampScroll(offset + delta, maxScroll);
    }

    private static Method publicMethod(Class<?> owner, String name, Class<?>... parameterTypes) {
        try {
            return owner.getMethod(name, parameterTypes);
        } catch (NoSuchMethodException exception) {
            return null;
        }
    }

    private static Field publicField(Class<?> owner, String name) {
        try {
            return owner.getField(name);
        } catch (NoSuchFieldException exception) {
            return null;
        }
    }

    private static Object invoke(Method method, Object receiver, Object... arguments) {
        try {
            return method.invoke(receiver, arguments);
        } catch (IllegalAccessException exception) {
            throw incompatibleApi("cannot invoke " + method, exception);
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof RuntimeException runtime) {
                throw runtime;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw incompatibleApi("client API call failed: " + method, cause);
        }
    }

    private static IllegalStateException incompatibleApi(String message, Throwable cause) {
        return new IllegalStateException("unsupported Minecraft 26.x client API: " + message, cause);
    }
}
