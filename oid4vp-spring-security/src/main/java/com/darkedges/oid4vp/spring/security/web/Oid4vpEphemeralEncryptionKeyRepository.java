package com.darkedges.oid4vp.spring.security.web;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;

/**
 * Holds response-encryption private keys generated fresh per Authorization Request (see
 * {@link Oid4vpAuthorizationRequestService}), so a {@code ResponseDecryptionKeyResolver} can find the
 * right one later — HAIP forbids reusing the same response-encryption key across requests, so unlike
 * {@link Oid4vpAuthorizationRequestRepository} there is no single request this is keyed by; a registration
 * can have several outstanding keys live at once.
 */
public interface Oid4vpEphemeralEncryptionKeyRepository {

    void save(String registrationId, JsonNode privateJwk, Instant expiresAt);

    /** All not-yet-expired keys saved for this registration, as a JWK Set ({@code {"keys": [...]}})  —
     * the shape a {@code ResponseDecryptionKeyResolver} returns, so the JWE's own {@code kid} picks the
     * right one. */
    JsonNode resolveLiveKeys(String registrationId, Instant now);
}
