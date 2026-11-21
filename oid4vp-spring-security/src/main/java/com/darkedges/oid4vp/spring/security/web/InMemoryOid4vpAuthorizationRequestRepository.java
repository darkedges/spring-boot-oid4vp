package com.darkedges.oid4vp.spring.security.web;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link Oid4vpAuthorizationRequestRepository}. Not safe for multi-instance deployments (each
 * instance has its own map) — a shared store (Redis, JDBC, ...) is the natural production replacement,
 * following the same interface.
 */
public final class InMemoryOid4vpAuthorizationRequestRepository implements Oid4vpAuthorizationRequestRepository {

    private final ConcurrentHashMap<String, Oid4vpAuthorizationRequestContext> byState = new ConcurrentHashMap<>();

    @Override
    public void save(Oid4vpAuthorizationRequestContext context) {
        byState.put(context.state(), context);
    }

    @Override
    public Optional<Oid4vpAuthorizationRequestContext> consume(String state, String registrationId) {
        // Removed only when it belongs to this registration: a state presented at another relying party's endpoint stays usable.
        AtomicReference<Oid4vpAuthorizationRequestContext> taken = new AtomicReference<>();
        byState.computeIfPresent(state, (key, context) -> {
            if (!context.registrationId().equals(registrationId)) return context;
            taken.set(context);
            return null;
        });
        Oid4vpAuthorizationRequestContext context = taken.get();
        if (context == null || context.isExpired(Instant.now())) {
            return Optional.empty();
        }
        return Optional.of(context);
    }

    @Override
    public Optional<Oid4vpAuthorizationRequestContext> consume(String state) {
        Oid4vpAuthorizationRequestContext context = byState.remove(state);
        if (context == null) {
            return Optional.empty();
        }
        if (context.isExpired(Instant.now())) {
            return Optional.empty();
        }
        return Optional.of(context);
    }
}
