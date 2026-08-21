package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class MCAceDispositionReviewCommandTest {
    @Test
    void permissionAndExactReviewSyntaxGateTheReviewer() {
        AtomicInteger reviews = new AtomicInteger();
        MCAceDispositionReviewCommand command = new MCAceDispositionReviewCommand(
                (player, operator, request) -> {
                    reviews.incrementAndGet();
                    assertEquals("Alice", player);
                    assertEquals("console", operator);
                    assertEquals("case-42", request.reviewTicket());
                    assertEquals("aa".repeat(32), request.sha256());
                    return new MCAceDispositionReviewCommand.ReviewResult(
                            MCAceDispositionReviewCommand.Status.AUTHORIZED,
                            Optional.of(DispositionAction.LIMIT), Optional.of("rule-a"),
                            Optional.of(7L), Optional.of(UUID.fromString(
                            "00000000-0000-0000-0000-000000000099")));
                });
        List<String> messages = new ArrayList<>();
        String[] arguments = {
                "review", "Alice", "case-42", "mod", "example.mod", "1.0", "AA".repeat(32)};

        command.execute(invocation(arguments, false, messages));
        assertEquals(0, reviews.get());
        command.execute(invocation(arguments, true, messages));
        assertEquals(1, reviews.get());
        assertTrue(messages.stream().anyMatch(message -> message.contains("authorized")));
    }

    @Test
    void malformedHashNeverReachesReviewer() {
        AtomicInteger reviews = new AtomicInteger();
        MCAceDispositionReviewCommand command = new MCAceDispositionReviewCommand(
                (player, operator, request) -> {
                    reviews.incrementAndGet();
                    return MCAceDispositionReviewCommand.ReviewResult.status(
                            MCAceDispositionReviewCommand.Status.FAILED);
                });

        command.execute(invocation(new String[] {
                "review", "Alice", "case-42", "mod", "example.mod", "1.0", "bad"},
                true, new ArrayList<>()));
        assertEquals(0, reviews.get());
    }

    private static SimpleCommand.Invocation invocation(
            String[] arguments, boolean permission, List<String> messages) {
        CommandSource source = (CommandSource) Proxy.newProxyInstance(
                MCAceDispositionReviewCommandTest.class.getClassLoader(),
                new Class<?>[] {CommandSource.class},
                (proxy, method, values) -> switch (method.getName()) {
                    case "hasPermission" -> permission;
                    case "sendMessage" -> { messages.add(String.valueOf(values[0])); yield null; }
                    default -> defaultValue(method.getReturnType());
                });
        return (SimpleCommand.Invocation) Proxy.newProxyInstance(
                MCAceDispositionReviewCommandTest.class.getClassLoader(),
                new Class<?>[] {SimpleCommand.Invocation.class},
                (proxy, method, values) -> "arguments".equals(method.getName()) ? arguments : source);
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        return null;
    }
}