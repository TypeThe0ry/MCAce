package com.ellan.mcace.launcher;

import com.ellan.mcace.protocol.launcher.LauncherException;

record LauncherVersion(int major, int minor, int patch) implements Comparable<LauncherVersion> {
    static LauncherVersion parse(String value) throws LauncherException {
        if (value == null || !value.matches("[0-9]{1,6}\\.[0-9]{1,6}\\.[0-9]{1,6}")) {
            throw new LauncherException("launcher version must use major.minor.patch");
        }
        String[] fields = value.split("\\.");
        try {
            return new LauncherVersion(
                    Integer.parseInt(fields[0]), Integer.parseInt(fields[1]), Integer.parseInt(fields[2]));
        } catch (NumberFormatException exception) {
            throw new LauncherException("launcher version is outside the supported range", exception);
        }
    }

    @Override public int compareTo(LauncherVersion other) {
        int result = Integer.compare(major, other.major);
        if (result == 0) result = Integer.compare(minor, other.minor);
        if (result == 0) result = Integer.compare(patch, other.patch);
        return result;
    }
}
