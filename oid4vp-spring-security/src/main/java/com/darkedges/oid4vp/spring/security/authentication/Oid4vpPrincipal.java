package com.darkedges.oid4vp.spring.security.authentication;

import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** The principal produced by a successful OpenID4VP presentation: the verified claims of every
 * Credential Query the Wallet satisfied, keyed by Credential Query id. */
public record Oid4vpPrincipal(Map<String, List<VerifiedPresentation>> presentations) implements Serializable {

    public Oid4vpPrincipal {
        presentations = Map.copyOf(presentations);
    }

    /** Looks up a claim within the first Presentation returned for the given Credential Query id, by a
     * path of successive object keys (e.g. {@code claim("pid", "ld", "credentialSubject", "givenName")}). */
    public Optional<JsonNode> claim(String credentialQueryId, String... path) {
        List<VerifiedPresentation> list = presentations.get(credentialQueryId);
        if (list == null || list.isEmpty()) {
            return Optional.empty();
        }
        JsonNode node = list.get(0).verifiedClaims();
        for (String segment : path) {
            if (node == null || !node.has(segment)) {
                return Optional.empty();
            }
            node = node.get(segment);
        }
        return Optional.ofNullable(node);
    }
}
