package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.BaseComponent;
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
                            Optional.of(DispositionAction.QUARANTINE), Optional.of("rule-a"),
                            Optional.of(7L), Optional.of(UUID.fromString(
                            "00000000-0000-0000-0000-000000000099")));
                });
        List<String> messages = new ArrayList<>();
        String[] arguments = {
                "review", "Alice", "case-42", "mod", "example.mod", "1.0", "AA".repeat(32)};

        command.execute(sender(false, messages), arguments);
        assertEquals(0, reviews.get());
        command.execute(sender(true, messages), arguments);
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
        command.execute(sender(true, new ArrayList<>()), new String[] {
                "review", "Alice", "case-42", "mod", "example.mod", "1.0", "bad"});
        assertEquals(0, reviews.get());
    }

    private static CommandSender sender(boolean permission, List<String> messages) {
        return (CommandSender) Proxy.newProxyInstance(
                MCAceDispositionReviewCommandTest.class.getClassLoader(),
                new Class<?>[] {CommandSender.class},
                (proxy, method, values) -> {
                    if ("hasPermission".equals(method.getName())) return permission;
                    if ("sendMessage".equals(method.getName())) {
                        Object value = values[0];
                        if (value instanceof BaseComponent component) {
                            messages.add(component.toPlainText());
                        } else if (value instanceof BaseComponent[] components) {
                            messages.add(BaseComponent.toPlainText(components));
                        }
                        return null;
                    }
                    if (method.getReturnType() == boolean.class) return false;
                    return null;
                });
    }
}