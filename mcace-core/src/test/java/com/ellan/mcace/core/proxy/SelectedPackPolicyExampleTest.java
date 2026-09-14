package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DispositionPolicyConfiguration;
import com.google.protobuf.TextFormat;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

final class SelectedPackPolicyExampleTest {
    @Test
    void selectedPackTemplateIsOptInAndAdvisory() throws Exception {
        Path example = repositoryExample();
        DispositionPolicyConfiguration.Builder builder = DispositionPolicyConfiguration.newBuilder();
        TextFormat.getParser().merge(Files.readString(example, StandardCharsets.UTF_8), builder);
        DispositionPolicyConfiguration configuration = builder.build();
        assertEquals(1, configuration.getCatalogEntriesCount());
        assertEquals(DetectionMatchType.DETECTION_MATCH_METADATA,
                configuration.getCatalogEntries(0).getSelector().getMatchType());
        assertEquals("true", configuration.getCatalogEntries(0).getSelector()
                .getMetadataOrThrow("selected"));
        assertFalse(configuration.getCatalogSelections(0).getEnabled());
    }

    private static Path repositoryExample() {
        for (Path directory = Path.of("").toAbsolutePath(); directory != null; directory = directory.getParent()) {
            Path example = directory.resolve("examples/selected-pack-policy.textproto");
            if (Files.isRegularFile(example)) return example;
        }
        throw new AssertionError("examples/selected-pack-policy.textproto is not available");
    }
}
