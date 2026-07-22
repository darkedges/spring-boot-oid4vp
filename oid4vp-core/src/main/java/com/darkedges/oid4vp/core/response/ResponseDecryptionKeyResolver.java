package com.darkedges.oid4vp.core.response;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Optional;

/**
 * Resolves the Verifier's private JWK Set used to decrypt an encrypted Authorization Response
 * ({@code direct_post.jwt} / {@code dc_api.jwt}), for a given relying-party registration id. Kept
 * crypto-library-agnostic here (this module has no JOSE dependency); the JWE decryption itself happens
 * in a crypto-aware module using whichever key in the returned set matches the JWE's {@code kid}/{@code alg}.
 */
public interface ResponseDecryptionKeyResolver {

    Optional<JsonNode> resolvePrivateJwks(String registrationId);
}
