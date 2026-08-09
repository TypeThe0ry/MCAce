package com.ellan.mcace.cloud;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class CloudConfigurationTest {
    @Test
    void defaultsToLoopbackAndReadsPasswordIndirectly() {
        Map<String, String> environment = baseEnvironment();
        environment.put("MCACE_DATABASE_PASSWORD_ENV", "TEST_DATABASE_SECRET");
        environment.put("TEST_DATABASE_SECRET", "not-logged-secret");

        CloudConfiguration configuration = CloudConfiguration.fromEnvironment(environment);

        assertEquals("127.0.0.1", configuration.bind().getAddress().getHostAddress());
        assertEquals(8088, configuration.bind().getPort());
        assertEquals("not-logged-secret", configuration.databasePassword());
        assertFalse(configuration.toString().contains("not-logged-secret"));
    }

    @Test
    void refusesRemotePlaintextBindingByDefault() {
        Map<String, String> environment = baseEnvironment();
        environment.put("MCACE_DATABASE_PASSWORD", "secret");
        environment.put("MCACE_CLOUD_BIND", "0.0.0.0");

        assertThrows(IllegalArgumentException.class,
                () -> CloudConfiguration.fromEnvironment(environment));
    }

    @Test
    void readsAuditAnchorCredentialIndirectlyAndRedactsIt() {
        Map<String, String> environment = baseEnvironment();
        environment.put("MCACE_DATABASE_PASSWORD", "database-secret");
        environment.put("MCACE_AUDIT_ANCHOR_URL", "https://ledger.example.test/v1/anchors");
        environment.put("MCACE_AUDIT_ANCHOR_BEARER_ENV", "TEST_ANCHOR_SECRET");
        environment.put("TEST_ANCHOR_SECRET", "external-ledger-secret");

        CloudConfiguration configuration = CloudConfiguration.fromEnvironment(environment);

        assertTrue(configuration.auditAnchor().isPresent());
        assertEquals("external-ledger-secret", configuration.auditAnchor().orElseThrow().bearerToken());
        assertFalse(configuration.toString().contains("external-ledger-secret"));
    }

    @Test
    void enablesWebPortalOnlyWithPathlessHttpsPublicOrigin() {
        Map<String, String> environment = baseEnvironment();
        environment.put("MCACE_DATABASE_PASSWORD", "database-secret");
        environment.put("MCACE_WEB_PUBLIC_ORIGIN", "https://Portal.Example.test:443/");

        CloudConfiguration configuration = CloudConfiguration.fromEnvironment(environment);

        assertEquals("https://portal.example.test", configuration.webPublicOrigin().orElseThrow().toString());
        environment.put("MCACE_WEB_PUBLIC_ORIGIN", "http://portal.example.test");
        assertThrows(IllegalArgumentException.class,
                () -> CloudConfiguration.fromEnvironment(environment));
        environment.put("MCACE_WEB_PUBLIC_ORIGIN", "https://portal.example.test/admin");
        assertThrows(IllegalArgumentException.class,
                () -> CloudConfiguration.fromEnvironment(environment));
    }

    private static Map<String, String> baseEnvironment() {
        Map<String, String> environment = new HashMap<>();
        environment.put("MCACE_DATABASE_URL", "jdbc:postgresql://127.0.0.1/mcace");
        environment.put("MCACE_DATABASE_USERNAME", "mcace");
        return environment;
    }
}
