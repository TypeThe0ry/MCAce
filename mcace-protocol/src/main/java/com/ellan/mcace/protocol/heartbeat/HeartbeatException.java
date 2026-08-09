package com.ellan.mcace.protocol.heartbeat;
public final class HeartbeatException extends Exception { private static final long serialVersionUID = 1L; public HeartbeatException(String m) { super(m); } public HeartbeatException(String m, Throwable c) { super(m,c); } }
