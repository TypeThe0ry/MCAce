package com.ellan.mcace.protocol.launcher;

public final class LauncherException extends Exception {
    private static final long serialVersionUID = 1L;

    public LauncherException(String message) { super(message); }
    public LauncherException(String message, Throwable cause) { super(message, cause); }
}
