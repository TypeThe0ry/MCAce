package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

final class MCAcePolicyCommandTest {
    @TempDir Path temporaryDirectory;

    @Test
    void previewAndValidateUseReadOnlyPermissionWhilePublishKeepsPolicyPermission() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        VelocityDispositionPolicyRuntime runtime = VelocityDispositionPolicyRuntime.create(
                temporaryDirectory.resolve("policy").resolve("signed-disposition-policy.pb"),
                Clock.systemUTC(), identity);
        VelocityDispositionPolicyPublisher publisher = VelocityDispositionPolicyPublisher.create(
                temporaryDirectory, Clock.systemUTC(), identity, runtime);
        MCAcePolicyCommand command = new MCAcePolicyCommand(
                new ServerPolicyManager(temporaryDirectory.resolve("signed-policy.pb"), Clock.systemUTC(), identity),
                identity.getPublic(), Clock.systemUTC(), LoggerFactory.getLogger("mcace-command-test"),
                runtime, publisher, VelocityAdmissionConfig.Mode.MONITOR);

        assertTrue(command.hasPermission(invocation(new String[] {"preview"}, true, false)));
        assertTrue(command.hasPermission(invocation(new String[] {"validate"}, true, false)));
        assertTrue(command.hasPermission(invocation(new String[] {"catalog", "preview"}, true, false)));
        assertTrue(command.hasPermission(invocation(new String[] {"publish"}, false, true)));
        assertTrue(command.hasPermission(invocation(new String[] {"catalog", "publish"}, false, true)));
        assertFalse(command.hasPermission(invocation(new String[] {"preview"}, false, true)));
    }

    private static SimpleCommand.Invocation invocation(
            String[] arguments, boolean checkPermission, boolean policyPermission) {
        CommandSource source = (CommandSource) Proxy.newProxyInstance(
                MCAcePolicyCommandTest.class.getClassLoader(), new Class<?>[] {CommandSource.class},
                (proxy, method, values) -> "hasPermission".equals(method.getName())
                        && ("mcace.admin.check".equals(String.valueOf(values[0]))
                        ? checkPermission : policyPermission));
        return (SimpleCommand.Invocation) Proxy.newProxyInstance(
                MCAcePolicyCommandTest.class.getClassLoader(), new Class<?>[] {SimpleCommand.Invocation.class},
                (proxy, method, values) -> "arguments".equals(method.getName())
                        ? arguments : source);
    }
}
