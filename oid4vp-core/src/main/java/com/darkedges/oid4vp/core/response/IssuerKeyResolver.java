package com.darkedges.oid4vp.core.response;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Optional;

/**
 * Resolves the public key (as a raw JWK JSON object) that should have signed a Credential/presentation
 * from a given issuer, keyed by an optional JOSE {@code kid}. Kept crypto-library-agnostic here (this
 * module has no JOSE dependency); format modules parse the returned JWK with whichever library they use.
 */
public interface IssuerKeyResolver {

    Optional<JsonNode> resolve(String issuer, Optional<String> keyId);
}
