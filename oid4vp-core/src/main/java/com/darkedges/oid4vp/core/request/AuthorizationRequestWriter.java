package com.darkedges.oid4vp.core.request;

import com.darkedges.oid4vp.core.dcql.DcqlQueryWriter;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Serializes an {@link AuthorizationRequest} to the JSON object of claims used as the payload of a
 * signed Request Object (OpenID4VP 1.1 / RFC9101 JAR): every Authorization Request parameter as a
 * top-level member.
 */
public final class AuthorizationRequestWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private AuthorizationRequestWriter() {}

    public static ObjectNode write(AuthorizationRequest request) {
        ObjectNode node = NODES.objectNode();
        node.put("response_type", request.responseType());
        node.put("client_id", request.clientId().fullClientId());
        node.put("response_mode", request.responseMode().value());
        request.responseUri().ifPresent(uri -> node.put("response_uri", uri));
        request.redirectUri().ifPresent(uri -> node.put("redirect_uri", uri));
        request.dcqlQuery().ifPresent(query -> node.set("dcql_query", DcqlQueryWriter.write(query)));
        request.scope().ifPresent(scope -> node.put("scope", scope));
        request.state().ifPresent(state -> node.put("state", state));
        node.put("nonce", request.nonce());
        request.clientMetadata().ifPresent(metadata -> node.set("client_metadata", ClientMetadataWriter.write(metadata)));
        if (request.requestUriMethod() == RequestUriMethod.POST) {
            node.put("request_uri_method", request.requestUriMethod().value());
        }
        if (!request.transactionData().isEmpty()) {
            ArrayNode array = node.putArray("transaction_data");
            request.transactionData().forEach(entry -> array.add(entry.raw()));
        }
        if (!request.verifierInfo().isEmpty()) {
            ArrayNode array = node.putArray("verifier_info");
            request.verifierInfo().forEach(entry -> {
                ObjectNode entryNode = NODES.objectNode();
                entryNode.put("format", entry.format());
                entryNode.set("data", entry.data());
                entry.credentialIds().ifPresent(ids -> {
                    ArrayNode idsArray = entryNode.putArray("credential_ids");
                    ids.forEach(idsArray::add);
                });
                array.add(entryNode);
            });
        }
        return node;
    }
}
