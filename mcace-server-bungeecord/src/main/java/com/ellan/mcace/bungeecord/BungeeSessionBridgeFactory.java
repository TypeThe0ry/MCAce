package com.ellan.mcace.bungeecord;

import java.nio.file.Path;
import java.util.logging.Logger;

/**
 * Service-provider hook for an installation-specific, shared-core MCAce bridge.
 *
 * <p>Providers are discovered through {@link java.util.ServiceLoader}; exactly one provider is
 * accepted. This keeps key management and signed-policy provisioning outside the proxy transport
 * adapter, where it can be shared with Velocity deployments.</p>
 */
public interface BungeeSessionBridgeFactory {
    BungeeSessionBridge create(Path dataDirectory, Logger logger) throws Exception;
}
