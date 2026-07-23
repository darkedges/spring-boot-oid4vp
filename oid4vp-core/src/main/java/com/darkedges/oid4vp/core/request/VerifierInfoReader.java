package com.darkedges.oid4vp.core.request;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Parses the {@code verifier_info} Authorization Request parameter (a JSON array) into
 * {@link VerifierInfoEntry} values — the inverse of the {@code verifier_info} handling in
 * {@link AuthorizationRequestWriter}. */
public final class VerifierInfoReader {

    private VerifierInfoReader() {}

    public static List<VerifierInfoEntry> read(JsonNode array) {
        List<VerifierInfoEntry> entries = new ArrayList<>();
        if (array == null || array.isMissingNode() || array.isNull()) {
            return entries;
        }
        for (JsonNode node : array) {
            String format = node.required("format").asText();
            JsonNode data = node.required("data");
            Optional<List<String>> credentialIds = Optional.empty();
            if (node.hasNonNull("credential_ids")) {
                List<String> ids = new ArrayList<>();
                node.get("credential_ids").forEach(id -> ids.add(id.asText()));
                credentialIds = Optional.of(ids);
            }
            entries.add(new VerifierInfoEntry(format, data, credentialIds));
        }
        return entries;
    }
}
