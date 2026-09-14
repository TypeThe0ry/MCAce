package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.core.session.AuthenticatedManifest;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.FileEntry;
import com.ellan.mcace.protocol.generated.IntegrityScopeManifest;
import com.ellan.mcace.protocol.generated.LoadedModEntry;
import com.ellan.mcace.protocol.generated.LoadedModOriginKind;
import com.ellan.mcace.protocol.generated.ModEntry;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.google.protobuf.ByteString;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class AuthenticatedManifestObservationDeriverTest {
    @Test
    void derivesEveryModsScopeEntryAndOnlyUsesReconciledModMetadata() {
        byte[] first = new byte[32]; first[0] = 1;
        byte[] second = new byte[32]; second[0] = 2;
        AuthRequest request = AuthRequest.newBuilder()
                .addMods(ModEntry.newBuilder().setId("known.mod").setVersion("1.0")
                        .setFilename("known.jar").setFileSize(10).setSha256(ByteString.copyFrom(first))
                        .setSigner("trusted").putMetadata("admin_classification", "allow"))
                .addScopeManifests(IntegrityScopeManifest.newBuilder().setScope("mods").setPresent(true)
                        .addEntries(file("known.jar", 10, first)).addEntries(file("hidden.jar", 20, second)))
                .build();
        AuthenticatedManifest manifest = new AuthenticatedManifest(UUID.randomUUID(), "session-123456789012",
                SecurityPolicy.getDefaultInstance(), request, Instant.parse("2026-08-08T00:00:00Z"));

        AuthenticatedManifestDerivation result = new AuthenticatedManifestObservationDeriver().derive(manifest);

        assertEquals(2, result.observations().size());
        ArtifactObservation known = result.observations().stream()
                .filter(observation -> observation.identifier().equals("known.mod")).findFirst().orElseThrow();
        ArtifactObservation unknown = result.observations().stream()
                .filter(observation -> observation.identifier().startsWith("unknown:")).findFirst().orElseThrow();
        assertTrue(!known.metadata().containsKey("signer"));
        assertTrue(!known.metadata().containsKey("admin_classification"));
        assertEquals(ArtifactType.MOD, unknown.type());
        assertEquals(ObservationOrigin.CLIENT_REPORTED, unknown.origin());
        assertEquals(Confidence.LOW, unknown.confidence());
        assertTrue(result.consistencyIssues().contains("mods-scope-entry-without-matching-mod-list-entry"));
    }

    @Test
    void marksOnlyAnExactRuntimeAndManifestBoundModAsLoaded() {
        byte[] hash = new byte[32]; hash[0] = 7;
        AuthRequest request = AuthRequest.newBuilder()
                .addMods(ModEntry.newBuilder().setId("loaded.mod").setVersion("1.0")
                        .setFilename("loaded.jar").setFileSize(10).setSha256(ByteString.copyFrom(hash)))
                .addLoadedMods(LoadedModEntry.newBuilder().setId("loaded.mod").setVersion("1.0")
                        .setOriginKind(LoadedModOriginKind.LOADED_MOD_ORIGIN_MODS_FILE)
                        .setOriginFilename("loaded.jar").setOriginFileSize(10)
                        .setOriginSha256(ByteString.copyFrom(hash)).setOriginManifestMatched(true))
                .addScopeManifests(IntegrityScopeManifest.newBuilder().setScope("mods").setPresent(true)
                        .addEntries(file("loaded.jar", 10, hash)))
                .build();

        AuthenticatedManifestDerivation result = new AuthenticatedManifestObservationDeriver()
                .derive(manifest(request));

        assertEquals(1, result.observations().size());
        ArtifactObservation observation = result.observations().getFirst();
        assertEquals("loaded.mod", observation.identifier());
        assertEquals("true", observation.metadata().get("loaded"));
        assertEquals("mods_file", observation.metadata().get("loaded_origin"));
        assertEquals("true", observation.metadata().get("origin_manifest_matched"));
        assertTrue(!result.consistencyIssues().contains("loaded-mod-manifest-binding-not-consumed"));
    }

    @Test
    void separatesDormantInstalledJarFromNestedRuntimeMod() {
        byte[] hash = new byte[32]; hash[0] = 8;
        AuthRequest request = AuthRequest.newBuilder()
                .addMods(ModEntry.newBuilder().setId("dormant.mod").setVersion("1")
                        .setFilename("dormant.jar").setFileSize(12).setSha256(ByteString.copyFrom(hash)))
                .addLoadedMods(LoadedModEntry.newBuilder().setId("nested.mod").setVersion("2")
                        .setOriginKind(LoadedModOriginKind.LOADED_MOD_ORIGIN_NESTED)
                        .setParentModId("parent.mod"))
                .addScopeManifests(IntegrityScopeManifest.newBuilder().setScope("mods").setPresent(true)
                        .addEntries(file("dormant.jar", 12, hash)))
                .build();

        List<ArtifactObservation> observations = new AuthenticatedManifestObservationDeriver()
                .derive(manifest(request)).observations();

        assertEquals("false", observations.stream().filter(item -> item.identifier().equals("dormant.mod"))
                .findFirst().orElseThrow().metadata().get("loaded"));
        ArtifactObservation nested = observations.stream().filter(item -> item.identifier().equals("nested.mod"))
                .findFirst().orElseThrow();
        assertEquals("true", nested.metadata().get("loaded"));
        assertEquals("nested", nested.metadata().get("loaded_origin"));
        assertEquals("parent.mod", nested.metadata().get("parent_mod_id"));
        assertEquals(null, nested.sha256());
    }

    @Test
    void mapsScopeEntriesToTheirFixedArtifactType() {
        byte[] hash = new byte[32]; hash[0] = 9;
        AuthRequest request = AuthRequest.newBuilder().addScopeManifests(
                IntegrityScopeManifest.newBuilder().setScope("resourcepacks").setPresent(true)
                        .addEntries(file("pack.zip", 1, hash))).build();
        AuthenticatedManifest manifest = new AuthenticatedManifest(UUID.randomUUID(), "session-123456789012",
                SecurityPolicy.getDefaultInstance(), request, Instant.now());

        ArtifactObservation observation = new AuthenticatedManifestObservationDeriver().derive(manifest)
                .observations().getFirst();

        assertEquals(ArtifactType.RESOURCE_PACK, observation.type());
        assertEquals("pack.zip", observation.identifier());
        assertEquals(Confidence.LOW, observation.confidence());
    }

    @Test
    void marksOnlyTheClientSelectedResourcePackAndShaderPackEntries() {
        byte[] resourceHash = new byte[32]; resourceHash[0] = 3;
        byte[] shaderHash = new byte[32]; shaderHash[0] = 4;
        AuthRequest request = AuthRequest.newBuilder()
                .addSelectedResourcePacks("file/xray.zip")
                .addSelectedShaderPacks("Complementary")
                .addScopeManifests(IntegrityScopeManifest.newBuilder().setScope("resourcepacks").setPresent(true)
                        .addEntries(file("xray.zip", 1, resourceHash))
                        .addEntries(file("clean.zip", 1, resourceHash)))
                .addScopeManifests(IntegrityScopeManifest.newBuilder().setScope("shaderpacks").setPresent(true)
                        .addEntries(file("Complementary/shaders.properties", 1, shaderHash))
                        .addEntries(file("Vanilla/shaders.properties", 1, shaderHash)))
                .build();

        List<ArtifactObservation> observations = new AuthenticatedManifestObservationDeriver()
                .derive(manifest(request)).observations();

        assertEquals("true", observations.stream()
                .filter(item -> item.identifier().equals("xray.zip"))
                .findFirst().orElseThrow().metadata().get("selected"));
        assertEquals("false", observations.stream()
                .filter(item -> item.identifier().equals("clean.zip"))
                .findFirst().orElseThrow().metadata().get("selected"));
        assertEquals("true", observations.stream()
                .filter(item -> item.identifier().equals("Complementary/shaders.properties"))
                .findFirst().orElseThrow().metadata().get("selected"));
        assertEquals("false", observations.stream()
                .filter(item -> item.identifier().equals("Vanilla/shaders.properties"))
                .findFirst().orElseThrow().metadata().get("selected"));
    }

    @Test
    void derivesDirectoryRootsFromRebasedEntriesIndependentOfTopLevelNameOrOrder() {
        byte[] first = new byte[32]; first[0] = 1;
        byte[] second = new byte[32]; second[0] = 2;
        AuthRequest request = AuthRequest.newBuilder().addScopeManifests(
                IntegrityScopeManifest.newBuilder().setScope("resourcepacks").setPresent(true)
                        .addEntries(file("pack-two/pack.mcmeta", 2, second))
                        .addEntries(file("pack-one/assets/a.txt", 1, first))
                        .addEntries(file("pack-two/assets/a.txt", 1, first))
                        .addEntries(file("pack-one/pack.mcmeta", 2, second))).build();

        List<ArtifactObservation> packages = new AuthenticatedManifestObservationDeriver()
                .derive(manifest(request)).observations().stream()
                .filter(observation -> "directory".equals(observation.metadata().get("package_kind")))
                .toList();

        assertEquals(2, packages.size());
        assertEquals(packages.get(0).metadata().get("content_root_sha256"),
                packages.get(1).metadata().get("content_root_sha256"));
        assertEquals(packages.get(0).identifier(), packages.get(1).identifier());
        assertEquals("resourcepacks", packages.get(0).metadata().get("scope"));
        assertEquals(ObservationOrigin.CLIENT_REPORTED, packages.get(0).origin());
        assertEquals(Confidence.LOW, packages.get(0).confidence());
    }

    @Test
    void directoryContentChangesChangeRootButArchivesAndLooseFilesDoNotCreateDirectoryRoots() {
        byte[] original = new byte[32]; original[0] = 3;
        byte[] changed = new byte[32]; changed[0] = 4;
        ArtifactObservation before = packageObservation(List.of(
                file("pack/assets/a.txt", 1, original), file("pack/pack.mcmeta", 2, original)));
        ArtifactObservation after = packageObservation(List.of(
                file("pack/assets/a.txt", 1, changed), file("pack/pack.mcmeta", 2, original)));
        assertTrue(!before.metadata().get("content_root_sha256")
                .equals(after.metadata().get("content_root_sha256")));

        AuthRequest request = AuthRequest.newBuilder().addScopeManifests(
                IntegrityScopeManifest.newBuilder().setScope("shaderpacks").setPresent(true)
                        .addEntries(file("single.zip", 1, original))
                        .addEntries(file("loose.bin", 2, changed))).build();
        List<ArtifactObservation> observations = new AuthenticatedManifestObservationDeriver()
                .derive(manifest(request)).observations();
        assertEquals(2, observations.size());
        assertTrue(observations.stream().noneMatch(item -> item.metadata().containsKey("package_kind")));
    }

    @Test
    void forgedClientMetadataDoesNotCreateContentRootsAndBadEntriesAreOnlyRecorded() {
        byte[] hash = new byte[32]; hash[0] = 5;
        AuthRequest request = AuthRequest.newBuilder()
                .addMods(ModEntry.newBuilder().setId("fake").setVersion("1").setFilename("fake.jar")
                        .setFileSize(1).setSha256(ByteString.copyFrom(hash))
                        .putMetadata("content_root_sha256", "ff".repeat(32)))
                .addScopeManifests(IntegrityScopeManifest.newBuilder().setScope("resourcepacks").setPresent(true)
                        .addEntries(file("pack/../evil", 1, hash))
                        .addEntries(FileEntry.newBuilder().setRelativePath("bad.bin").setFileSize(1)
                                .setSha256(ByteString.copyFrom(new byte[3])))).build();

        AuthenticatedManifestDerivation result = new AuthenticatedManifestObservationDeriver()
                .derive(manifest(request));

        assertTrue(result.observations().isEmpty());
        assertTrue(result.consistencyIssues().contains("invalid-scope-entry"));
        assertTrue(result.observations().stream().noneMatch(item -> item.metadata().containsKey("package_kind")));
    }

    @Test
    void observationBudgetIsBoundedAndFailsClosedWithoutPunitiveDisposition() {
        byte[] hash = new byte[32];
        IntegrityScopeManifest.Builder scope = IntegrityScopeManifest.newBuilder()
                .setScope("shaderpacks").setPresent(true);
        for (int index = 0; index < 16_385; index++) {
            scope.addEntries(file("file-" + index + ".zip", index, hash));
        }
        AuthenticatedManifestDerivation result = new AuthenticatedManifestObservationDeriver()
                .derive(manifest(AuthRequest.newBuilder().addScopeManifests(scope).build()));
        assertEquals(16_384, result.observations().size());
        assertTrue(result.consistencyIssues().contains("derived-observation-limit"));
        assertTrue(result.observations().stream().allMatch(item -> item.origin() == ObservationOrigin.CLIENT_REPORTED));
    }

    private static ArtifactObservation packageObservation(List<FileEntry> entries) {
        List<ArtifactObservation> observations = new AuthenticatedManifestObservationDeriver()
                .derive(manifest(AuthRequest.newBuilder().addScopeManifests(
                        IntegrityScopeManifest.newBuilder().setScope("resourcepacks").setPresent(true)
                                .addAllEntries(entries)).build())).observations();
        return observations.stream().filter(item -> "directory".equals(item.metadata().get("package_kind")))
                .findFirst().orElseThrow();
    }

    private static AuthenticatedManifest manifest(AuthRequest request) {
        return new AuthenticatedManifest(UUID.randomUUID(), "session-123456789012",
                SecurityPolicy.getDefaultInstance(), request, Instant.parse("2026-08-08T00:00:00Z"));
    }

    private static FileEntry file(String path, long size, byte[] hash) {
        return FileEntry.newBuilder().setRelativePath(path).setFileSize(size)
                .setSha256(ByteString.copyFrom(hash)).build();
    }
}
