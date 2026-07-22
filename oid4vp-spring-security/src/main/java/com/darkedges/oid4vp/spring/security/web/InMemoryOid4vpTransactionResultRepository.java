package com.darkedges.oid4vp.spring.security.web;

import org.springframework.security.core.Authentication;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link Oid4vpTransactionResultRepository}. Not safe for multi-instance deployments — see
 * {@link InMemoryOid4vpAuthorizationRequestRepository} for the same caveat. */
public final class InMemoryOid4vpTransactionResultRepository implements Oid4vpTransactionResultRepository {

    private record Entry(String responseCode, Authentication authentication, Instant expiresAt) {}

    private final ConcurrentHashMap<String, Entry> byTransactionId = new ConcurrentHashMap<>();
    private final Clock clock;
    private final Duration ttl;

    public InMemoryOid4vpTransactionResultRepository(Clock clock, Duration ttl) {
        this.clock = clock;
        this.ttl = ttl;
    }

    public InMemoryOid4vpTransactionResultRepository() {
        this(Clock.systemUTC(), Duration.ofMinutes(10));
    }

    @Override
    public void save(String transactionId, String responseCode, Authentication authentication) {
        byTransactionId.put(transactionId, new Entry(responseCode, authentication, clock.instant().plus(ttl)));
    }

    @Override
    public Optional<Authentication> consume(String transactionId, String responseCode) {
        Entry entry = byTransactionId.remove(transactionId);
        if (entry == null || clock.instant().isAfter(entry.expiresAt()) || !entry.responseCode().equals(responseCode)) {
            return Optional.empty();
        }
        return Optional.of(entry.authentication());
    }
}
