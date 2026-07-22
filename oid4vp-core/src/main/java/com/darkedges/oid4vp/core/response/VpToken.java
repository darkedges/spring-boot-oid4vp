package com.darkedges.oid4vp.core.response;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The {@code vp_token} Authorization Response parameter: a JSON object mapping each satisfied Credential
 * Query {@code id} to an array of Presentations. Optional Credential Queries with no match have their key
 * absent entirely (never an empty array).
 */
public record VpToken(Map<String, List<PresentationEntry>> presentations) {

    public VpToken {
        if (presentations == null || presentations.isEmpty()) {
            throw new IllegalArgumentException("vp_token must contain at least one credential query id");
        }
        Map<String, List<PresentationEntry>> copy = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, List<PresentationEntry>> entry : presentations.entrySet()) {
            if (entry.getValue() == null || entry.getValue().isEmpty()) {
                throw new IllegalArgumentException("vp_token entry \"" + entry.getKey() + "\" must be a non-empty array");
            }
            copy.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        presentations = Map.copyOf(copy);
    }

    public Optional<List<PresentationEntry>> get(String credentialQueryId) {
        return Optional.ofNullable(presentations.get(credentialQueryId));
    }
}
