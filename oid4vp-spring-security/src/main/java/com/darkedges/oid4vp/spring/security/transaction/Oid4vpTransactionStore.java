package com.darkedges.oid4vp.spring.security.transaction;

import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;

import java.time.Instant;
import java.util.Optional;

/**
 * Keeps {@link Oid4vpTransaction}s and their results. Every lookup names the tenant: another tenant's transaction is not found.
 * A transaction is answered at most once, and its result collected at most once, also when several instances race.
 */
public interface Oid4vpTransactionStore {

    /** @param resultCollected whether the result has been handed out; {@code resultExpiresAt} bounds how long it waits */
    record Answer(boolean resultCollected, Instant resultExpiresAt) {}

    void save(Oid4vpTransaction transaction);

    Optional<Oid4vpTransaction> find(String tenantId, String transactionId);

    Optional<Oid4vpTransaction> findByRequestId(String tenantId, String requestId);

    /** Records the verified result; {@code false}, changing nothing, when the transaction already has one. */
    boolean answer(Oid4vpTransaction transaction, Oid4vpPrincipal result, Instant resultExpiresAt);

    /** The transaction's answer, if it has one. */
    Optional<Answer> answerOf(Oid4vpTransaction transaction);

    /** The result, once: empty when there is none, it was already collected, or it waited too long. */
    Optional<Oid4vpPrincipal> collect(Oid4vpTransaction transaction);
}
