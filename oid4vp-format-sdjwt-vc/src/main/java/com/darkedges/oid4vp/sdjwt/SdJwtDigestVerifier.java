package com.darkedges.oid4vp.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verifies SD-JWT selective disclosure digests: recursively walks the Issuer-signed JWT payload,
 * resolving each {@code _sd} array entry (object properties) and {@code {"...": <digest>}} marker (array
 * elements) against the provided {@link Disclosure}s, and merges disclosed claims back into the tree.
 *
 * <p>An {@code _sd} digest with no matching disclosure is normal (the claim simply wasn't disclosed) and
 * is silently dropped. A <em>disclosure</em> that cannot be matched to any digest anywhere in the payload
 * is an error (an invalid/extraneous disclosure) and aborts verification.
 */
public final class SdJwtDigestVerifier {

    private SdJwtDigestVerifier() {}

    public static JsonNode verify(JsonNode payload, List<Disclosure> disclosures, String hashAlg) {
        Map<String, Disclosure> byDigest = new HashMap<>();
        for (Disclosure disclosure : disclosures) {
            byDigest.put(disclosure.digest(hashAlg), disclosure);
        }

        Set<String> consumedDigests = new HashSet<>();
        JsonNode result = process(payload, byDigest, consumedDigests);

        if (consumedDigests.size() != byDigest.size()) {
            Set<String> unmatched = new HashSet<>(byDigest.keySet());
            unmatched.removeAll(consumedDigests);
            throw new SdJwtVerificationException(
                    "disclosure(s) could not be matched to any _sd digest in the payload: " + unmatched);
        }

        return result;
    }

    public static JsonNode verify(JsonNode payload, List<Disclosure> disclosures) {
        return verify(payload, disclosures, HashAlgorithms.DEFAULT);
    }

    private static JsonNode process(JsonNode node, Map<String, Disclosure> byDigest, Set<String> consumedDigests) {
        if (node.isObject()) {
            return processObject(node, byDigest, consumedDigests);
        }
        if (node.isArray()) {
            return processArray(node, byDigest, consumedDigests);
        }
        return node;
    }

    private static JsonNode processObject(JsonNode node, Map<String, Disclosure> byDigest, Set<String> consumedDigests) {
        ObjectNode result = JsonNodeFactory.instance.objectNode();
        node.fields().forEachRemaining(entry -> {
            String key = entry.getKey();
            if (key.equals("_sd") || key.equals("_sd_alg")) {
                return;
            }
            result.set(key, process(entry.getValue(), byDigest, consumedDigests));
        });

        if (node.has("_sd")) {
            for (JsonNode digestNode : node.get("_sd")) {
                String digest = digestNode.asText();
                Disclosure disclosure = byDigest.get(digest);
                if (disclosure != null && disclosure.claimName().isPresent()) {
                    consumedDigests.add(digest);
                    result.set(disclosure.claimName().get(), process(disclosure.claimValue(), byDigest, consumedDigests));
                }
                // else: digest present but not disclosed -- normal, not an error.
            }
        }
        return result;
    }

    private static JsonNode processArray(JsonNode node, Map<String, Disclosure> byDigest, Set<String> consumedDigests) {
        ArrayNode result = JsonNodeFactory.instance.arrayNode();
        for (JsonNode element : node) {
            if (element.isObject() && element.size() == 1 && element.has("...")) {
                String digest = element.get("...").asText();
                Disclosure disclosure = byDigest.get(digest);
                if (disclosure != null && disclosure.claimName().isEmpty()) {
                    consumedDigests.add(digest);
                    result.add(process(disclosure.claimValue(), byDigest, consumedDigests));
                }
                // else: array element digest present but not disclosed -- normal, not an error.
            } else {
                result.add(process(element, byDigest, consumedDigests));
            }
        }
        return result;
    }
}
