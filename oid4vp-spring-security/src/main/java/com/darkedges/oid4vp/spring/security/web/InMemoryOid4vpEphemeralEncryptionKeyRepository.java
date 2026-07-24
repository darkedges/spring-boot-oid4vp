package com.darkedges.oid4vp.spring.security.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link Oid4vpEphemeralEncryptionKeyRepository}. Not safe for multi-instance deployments (each
 * instance has its own map) — a shared store (Redis, JDBC, ...) is the natural production replacement,
 * following the same interface, same caveat as {@link InMemoryOid4vpAuthorizationRequestRepository}.
 */
public final class InMemoryOid4vpEphemeralEncryptionKeyRepository implements Oid4vpEphemeralEncryptionKeyRepository {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private record Entry(String registrationId, JsonNode privateJwk, Instant expiresAt) {}

    private final ConcurrentHashMap<String, Entry> byKeyId = new ConcurrentHashMap<>();

    @Override
    public void save(String registrationId, JsonNode privateJwk, Instant expiresAt) {
        String kid = privateJwk.path("kid").asText(null);
        if (kid == null || kid.isBlank()) {
            throw new IllegalArgumentException("privateJwk must have a \"kid\"");
        }
        byKeyId.put(kid, new Entry(registrationId, privateJwk, expiresAt));
    }

    @Override
    public JsonNode resolveLiveKeys(String registrationId, Instant now) {
        byKeyId.entrySet().removeIf(e -> now.isAfter(e.getValue().expiresAt()));

        List<JsonNode> live = byKeyId.values().stream()
                .filter(entry -> entry.registrationId().equals(registrationId))
                .map(Entry::privateJwk)
                .toList();

        ObjectNode jwks = MAPPER.createObjectNode();
        ArrayNode keys = jwks.putArray("keys");
        live.forEach(keys::add);
        return jwks;
    }
}
