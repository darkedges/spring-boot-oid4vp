package com.darkedges.oid4vp.spring.security.transaction;

import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryOid4vpTransactionStoreTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private final InMemoryOid4vpTransactionStore store = new InMemoryOid4vpTransactionStore(Clock.fixed(NOW, ZoneOffset.UTC));
    private final Oid4vpPrincipal result = new Oid4vpPrincipal(Map.of());

    private Oid4vpTransaction saved() {
        Oid4vpTransaction transaction = new Oid4vpTransaction("tx", "req", "bank/staff", Optional.empty(), Map.of(), NOW.plusSeconds(60));
        store.save(transaction);
        return transaction;
    }

    @Test
    void isFoundByItsTenantOnly() {
        Oid4vpTransaction transaction = saved();
        assertThat(store.find("bank", "tx")).contains(transaction);
        assertThat(store.findByRequestId("bank", "req")).contains(transaction);
        assertThat(store.find("shop", "tx")).isEmpty();
        assertThat(store.findByRequestId("shop", "req")).isEmpty();
        assertThat(store.find("bank", "req")).as("a request id is not a transaction id").isEmpty();
    }

    @Test
    void isAnsweredOnceAndCollectedOnce() {
        Oid4vpTransaction transaction = saved();
        assertThat(store.answerOf(transaction)).isEmpty();
        assertThat(store.collect(transaction)).isEmpty();

        assertThat(store.answer(transaction, result, NOW.plusSeconds(60))).isTrue();
        assertThat(store.answer(transaction, result, NOW.plusSeconds(600))).isFalse();
        assertThat(store.answerOf(transaction)).contains(new Oid4vpTransactionStore.Answer(false, NOW.plusSeconds(60)));

        assertThat(store.collect(transaction)).contains(result);
        assertThat(store.collect(transaction)).isEmpty();
        assertThat(store.answerOf(transaction)).contains(new Oid4vpTransactionStore.Answer(true, NOW.plusSeconds(60)));
        assertThat(store.answer(transaction, result, NOW.plusSeconds(60))).as("still answered once collected").isFalse();
    }

    @Test
    void aResultThatWaitedTooLongIsNotCollected() {
        Oid4vpTransaction transaction = saved();
        store.answer(transaction, result, NOW.minusSeconds(1));
        assertThat(store.collect(transaction)).isEmpty();
    }
}
