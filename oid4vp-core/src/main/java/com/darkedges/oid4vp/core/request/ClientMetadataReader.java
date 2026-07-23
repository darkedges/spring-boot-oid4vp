package com.darkedges.oid4vp.core.request;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Parses a {@link ClientMetadata} (the {@code client_metadata} request parameter) from its JSON
 * representation — the inverse of {@link ClientMetadataWriter}. */
public final class ClientMetadataReader {

    private ClientMetadataReader() {}

    public static ClientMetadata read(JsonNode root) {
        Optional<JsonNode> jwks = root.hasNonNull("jwks") ? Optional.of(root.get("jwks")) : Optional.empty();

        List<String> encValues = new ArrayList<>();
        if (root.hasNonNull("encrypted_response_enc_values_supported")) {
            root.get("encrypted_response_enc_values_supported").forEach(n -> encValues.add(n.asText()));
        }

        Map<CredentialFormat, JsonNode> vpFormats = new LinkedHashMap<>();
        if (root.hasNonNull("vp_formats_supported")) {
            root.get("vp_formats_supported").fields().forEachRemaining(entry ->
                    vpFormats.put(CredentialFormat.fromIdentifier(entry.getKey()), entry.getValue()));
        }

        return new ClientMetadata(jwks, encValues, vpFormats);
    }
}
