package com.ellan.mcace.protocol.heartbeat;
/** Transport health only; neither STALE nor MISSING is a cheat finding or punishment instruction. */
public enum HeartbeatHealth { ACTIVE, STALE, MISSING }
