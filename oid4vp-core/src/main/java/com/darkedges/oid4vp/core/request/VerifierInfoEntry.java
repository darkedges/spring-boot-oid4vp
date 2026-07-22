package com.darkedges.oid4vp.core.request;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Optional;

/**
 * One entry of the {@code verifier_info} Authorization Request parameter (Verifier Attestation-style
 * proof-of-possession objects).
 *
 * @param format        REQUIRED.
 * @param data          REQUIRED, format-specific (e.g. a JWT).
 * @param credentialIds OPTIONAL, scopes which Credential Queries this applies to.
 */
public record VerifierInfoEntry(String format, JsonNode data, Optional<List<String>> credentialIds) {

    public VerifierInfoEntry {
        if (format == null || format.isBlank()) {
            throw new IllegalArgumentException("format is required");
        }
        if (data == null) {
            throw new IllegalArgumentException("data is required");
        }
        credentialIds = credentialIds == null ? Optional.empty() : credentialIds.map(List::copyOf);
    }
}
