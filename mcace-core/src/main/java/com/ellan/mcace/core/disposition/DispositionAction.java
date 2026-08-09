package com.ellan.mcace.core.disposition;

/** Ordered by fixed operational severity. Permanent bans are deliberately not modelled here. */
public enum DispositionAction {
    ALLOW(0), OBSERVE(1), NOTICE(2), WARN(3), CHALLENGE(4), LIMIT(5), QUARANTINE(6), DENY(7);
    private final int severity;
    DispositionAction(int severity) { this.severity = severity; }
    public int severity() { return severity; }
}
