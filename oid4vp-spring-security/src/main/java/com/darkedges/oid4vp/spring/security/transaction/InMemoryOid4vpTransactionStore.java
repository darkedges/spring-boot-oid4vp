package com.darkedges.oid4vp.spring.security.transaction;

import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/** In-memory {@link Oid4vpTransactionStore}, for a single instance. */
public final class InMemoryOid4vpTransactionStore implements Oid4vpTransactionStore {

    /** How long a transaction is still reported (as expired or collected) after it expires. */
    private static final Duration RETENTION = Duration.ofHours(1);

    private record Entry(Oid4vpTransaction transaction, Oid4vpPrincipal result, Instant resultExpiresAt) {}

    private final Map<String, Entry> byId = new ConcurrentHashMap<>();
    private final Map<String, String> idByRequestId = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryOid4vpTransactionStore() {
        this(Clock.systemUTC());
    }

    public InMemoryOid4vpTransactionStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void save(Oid4vpTransaction transaction) {
        sweep();
        byId.put(transaction.transactionId(), new Entry(transaction, null, null));
        idByRequestId.put(transaction.requestId(), transaction.transactionId());
    }

    @Override
    public Optional<Oid4vpTransaction> find(String tenantId, String transactionId) {
        return Optional.ofNullable(byId.get(transactionId)).map(Entry::transaction)
                .filter(transaction -> transaction.tenantId().equals(tenantId));
    }

    @Override
    public Optional<Oid4vpTransaction> findByRequestId(String tenantId, String requestId) {
        return Optional.ofNullable(idByRequestId.get(requestId)).flatMap(id -> find(tenantId, id));
    }

    @Override
    public boolean answer(Oid4vpTransaction transaction, Oid4vpPrincipal result, Instant resultExpiresAt) {
        AtomicReference<Boolean> answered = new AtomicReference<>(false);
        byId.computeIfPresent(transaction.transactionId(), (id, entry) -> {
            if (entry.resultExpiresAt() != null) return entry;
            answered.set(true);
            return new Entry(entry.transaction(), result, resultExpiresAt);
        });
        return answered.get();
    }

    @Override
    public Optional<Answer> answerOf(Oid4vpTransaction transaction) {
        return Optional.ofNullable(byId.get(transaction.transactionId())).filter(entry -> entry.resultExpiresAt() != null)
                .map(entry -> new Answer(entry.result() == null, entry.resultExpiresAt()));
    }

    @Override
    public Optional<Oid4vpPrincipal> collect(Oid4vpTransaction transaction) {
        AtomicReference<Oid4vpPrincipal> taken = new AtomicReference<>();
        byId.computeIfPresent(transaction.transactionId(), (id, entry) -> {
            if (entry.result() == null || !entry.resultExpiresAt().isAfter(clock.instant())) return entry;
            taken.set(entry.result());
            return new Entry(entry.transaction(), null, entry.resultExpiresAt());
        });
        return Optional.ofNullable(taken.get());
    }

    private void sweep() {
        Instant cutoff = clock.instant().minus(RETENTION);
        byId.values().removeIf(entry -> {
            boolean old = entry.transaction().expiresAt().isBefore(cutoff)
                    && (entry.resultExpiresAt() == null || entry.resultExpiresAt().isBefore(cutoff));
            if (old) idByRequestId.remove(entry.transaction().requestId());
            return old;
        });
    }
}
