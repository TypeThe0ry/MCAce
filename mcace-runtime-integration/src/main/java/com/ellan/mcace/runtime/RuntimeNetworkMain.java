package com.ellan.mcace.runtime;

import java.nio.file.Path;
import java.util.UUID;

public final class RuntimeNetworkMain {
    private RuntimeNetworkMain() {
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length == 2 && "server".equals(arguments[0])) {
            new RuntimeProtocolServer(RuntimeFixture.create()).run(Integer.parseInt(arguments[1]));
            return;
        }
        if (arguments.length == 7 && "client".equals(arguments[0])) {
            new RuntimeProtocolClient().run(
                    Integer.parseInt(arguments[1]),
                    RuntimeProtocolClient.decodeRoot(arguments[2]),
                    RuntimeScenario.valueOf(arguments[3]),
                    arguments[4],
                    UUID.fromString(arguments[5]),
                    Path.of(arguments[6]));
            return;
        }
        throw new IllegalArgumentException("usage: server <connections> or client <port> <root> <scenario> <label> <uuid> <cache>");
    }
}
