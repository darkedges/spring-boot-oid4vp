package com.darkedges.oid4vp.core.request;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Optional;

/**
 * Resolves the Verifier's private signing key (a single raw JWK JSON object, including its private key
 * material) used to sign an Authorization Request Object (JAR) for a given relying-party registration.
 * Kept crypto-library-agnostic here; the actual signing happens in a crypto-aware module.
 */
public interface RequestObjectSigningKeyResolver {

    Optional<JsonNode> resolveSigningKey(String registrationId);
}
