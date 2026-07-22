package com.darkedges.oid4vp.core.request;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * One entry of the {@code transaction_data} Authorization Request parameter, decoded from its
 * base64url-encoded JSON representation.
 *
 * @param type          REQUIRED transaction data type identifier.
 * @param credentialIds REQUIRED non-empty array of Credential Query {@code id}s this applies to.
 * @param raw           the full decoded JSON object, for access to type-specific extension fields.
 */
public record TransactionDataEntry(String type, List<String> credentialIds, JsonNode raw) {

    public TransactionDataEntry {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("type is required");
        }
        if (credentialIds == null || credentialIds.isEmpty()) {
            throw new IllegalArgumentException("credential_ids must be a non-empty array");
        }
        credentialIds = List.copyOf(credentialIds);
    }
}
