package com.ellan.mcace.core.proxy;

/**
 * The proxy integration that owns a runtime instance.  This label is diagnostic only: policy
 * verification and disposition evaluation deliberately do not branch on proxy implementation.
 */
public enum ProxyFamily {
    VELOCITY,
    BUNGEECORD
}
