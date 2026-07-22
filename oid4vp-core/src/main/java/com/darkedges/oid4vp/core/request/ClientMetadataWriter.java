package com.darkedges.oid4vp.core.request;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Serializes {@link ClientMetadata} to its JSON representation (the {@code client_metadata} request
 * parameter value). */
public final class ClientMetadataWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private ClientMetadataWriter() {}

    public static ObjectNode write(ClientMetadata metadata) {
        ObjectNode node = NODES.objectNode();
        metadata.jwks().ifPresent(jwks -> node.set("jwks", jwks));
        if (!metadata.encryptedResponseEncValuesSupported().isEmpty()) {
            ArrayNode array = node.putArray("encrypted_response_enc_values_supported");
            metadata.encryptedResponseEncValuesSupported().forEach(array::add);
        }
        if (!metadata.vpFormatsSupported().isEmpty()) {
            ObjectNode formats = node.putObject("vp_formats_supported");
            for (var entry : metadata.vpFormatsSupported().entrySet()) {
                formats.set(entry.getKey().identifier(), entry.getValue());
            }
        }
        return node;
    }
}
