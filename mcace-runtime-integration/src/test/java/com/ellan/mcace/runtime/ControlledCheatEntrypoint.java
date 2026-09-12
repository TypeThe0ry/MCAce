package com.ellan.mcace.runtime;

/**
 * Executable code embedded in the test-only controlled cheat fixture JAR.
 *
 * <p>This class intentionally has no product or network dependencies. The live fixture test
 * loads it through an isolated {@code URLClassLoader}; loading the class is the observable
 * client-side execution event. The resulting marker is sent alongside the mod-list observation
 * and is never treated as server authority by itself.</p>
 */
public final class ControlledCheatEntrypoint {
    private ControlledCheatEntrypoint() {
    }

    public static String execute() {
        return "CONTROLLED_CHEAT_FIXTURE_EXECUTED";
    }
}
