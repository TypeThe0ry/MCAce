package com.ellan.mcace.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.generated.ArtifactObservationUpdate;
import com.ellan.mcace.protocol.generated.ArtifactObservationResult;
import com.ellan.mcace.protocol.generated.ArtifactObservationResultReason;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.ClientCapability;
import com.ellan.mcace.protocol.generated.LoadedModEntry;
import com.ellan.mcace.protocol.generated.LoadedModOriginKind;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.google.protobuf.ByteString;
import java.util.List;
import org.junit.jupiter.api.Test;

final class LoadedModProtocolTest {
    @Test
    void additiveFieldNumbersAndRuntimeOriginRoundTripRemainStable() throws Exception {
        assertEquals(13, AuthRequest.getDescriptor().findFieldByName("loaded_mods").getNumber());
        assertEquals(14, AuthRequest.getDescriptor()
                .findFieldByName("client_capabilities").getNumber());
        assertEquals(12, ArtifactObservationUpdate.getDescriptor()
                .findFieldByName("loaded_mods").getNumber());
        assertEquals(13, ArtifactObservationUpdate.getDescriptor()
                .findFieldByName("client_capabilities").getNumber());
        assertEquals(14, SecurityPolicy.getDescriptor()
                .findFieldByName("required_client_capabilities").getNumber());
        assertEquals(23, PacketType.ARTIFACT_OBSERVATION_RESULT.getNumber());
        assertEquals(1, ArtifactObservationResult.getDescriptor()
                .findFieldByName("session_id").getNumber());
        assertEquals(2, ArtifactObservationResult.getDescriptor()
                .findFieldByName("update_sequence").getNumber());
        assertEquals(3, ArtifactObservationResult.getDescriptor()
                .findFieldByName("aggregate_root_sha256").getNumber());
        assertEquals(4, ArtifactObservationResult.getDescriptor()
                .findFieldByName("accepted").getNumber());
        assertEquals(5, ArtifactObservationResult.getDescriptor()
                .findFieldByName("reason").getNumber());
        assertEquals(6, ArtifactObservationResult.getDescriptor()
                .findFieldByName("retry_after_epoch_ms").getNumber());
        assertEquals(7, ArtifactObservationResult.getDescriptor()
                .findFieldByName("update_sha256").getNumber());
        byte[] hash = new byte[32]; hash[0] = 4;
        LoadedModEntry entry = LoadedModEntry.newBuilder()
                .setId("example.mod")
                .setVersion("1.2.3")
                .setOriginKind(LoadedModOriginKind.LOADED_MOD_ORIGIN_MODS_FILE)
                .setOriginFilename("example.jar")
                .setOriginFileSize(42)
                .setOriginSha256(ByteString.copyFrom(hash))
                .setOriginManifestMatched(true)
                .build();

        AuthRequest decoded = AuthRequest.parseFrom(AuthRequest.newBuilder()
                .addLoadedMods(entry)
                .addClientCapabilities(ClientCapability.CLIENT_CAPABILITY_LOADED_MOD_GRAPH_V1)
                .build()
                .toByteArray());

        assertEquals(entry, decoded.getLoadedMods(0));
        assertEquals(
                List.of(ClientCapability.CLIENT_CAPABILITY_LOADED_MOD_GRAPH_V1),
                decoded.getClientCapabilitiesList());
        assertTrue(decoded.getLoadedMods(0).getOriginManifestMatched());

        ArtifactObservationResult accepted = ArtifactObservationResult.parseFrom(
                ArtifactObservationResult.newBuilder()
                        .setSessionId("session-1")
                        .setUpdateSequence(7L)
                        .setAggregateRootSha256(ByteString.copyFrom(hash))
                        .setAccepted(true)
                        .setReason(ArtifactObservationResultReason.ARTIFACT_OBSERVATION_RESULT_ACCEPTED)
                        .setUpdateSha256(ByteString.copyFrom(hash))
                        .build()
                        .toByteArray());
        assertTrue(accepted.getAccepted());
        assertEquals(7L, accepted.getUpdateSequence());
        assertEquals(ArtifactObservationResultReason.ARTIFACT_OBSERVATION_RESULT_ACCEPTED,
                accepted.getReason());
    }
}
