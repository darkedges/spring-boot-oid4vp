package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A response (its {@code state}) belongs to the relying party that issued the request: it must not be accepted at another relying
 * party's endpoint, and presenting it there must not burn the genuine transaction.
 */
class StateBoundToRegistrationTest {

    private static Oid4vpAuthorizationRequestContext context(String registrationId, String state, Instant expiresAt) {
        DcqlQuery dcql = DcqlQuery.of(List.of(CredentialQuery.builder("employee", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://demo.oid4vp.example/employee_credential"))).build()));
        return new Oid4vpAuthorizationRequestContext(registrationId, state, "nonce-" + state,
                new ClientIdentifierPrefix.X509SanDns("verifier.example.org"), dcql,
                URI.create("https://verifier.example.org/login/oid4vp/direct-post/" + registrationId), expiresAt);
    }

    private static Instant later() { return Instant.now().plusSeconds(300); }

    @Test
    void theInMemoryRepositoryConsumesOnlyForTheIssuingRegistrationAndLeavesItOtherwise() {
        var repository = new InMemoryOid4vpAuthorizationRequestRepository();
        repository.save(context("bank", "s-1", later()));

        assertThat(repository.consume("s-1", "other")).isEmpty();
        // Still there for the genuine response.
        assertThat(repository.consume("s-1", "bank")).get().extracting(Oid4vpAuthorizationRequestContext::registrationId).isEqualTo("bank");
        // Single use.
        assertThat(repository.consume("s-1", "bank")).isEmpty();
    }

    @Test
    void anExpiredRequestIsNotReturnedEvenToItsOwnRegistration() {
        var repository = new InMemoryOid4vpAuthorizationRequestRepository();
        repository.save(context("bank", "s-2", Instant.now().minusSeconds(1)));
        assertThat(repository.consume("s-2", "bank")).isEmpty();
    }

    @Test
    void anOlderRepositoryStillRefusesAMismatchThroughTheDefaultMethod() {
        var map = new ConcurrentHashMap<String, Oid4vpAuthorizationRequestContext>();
        Oid4vpAuthorizationRequestRepository older = new Oid4vpAuthorizationRequestRepository() {
            @Override public void save(Oid4vpAuthorizationRequestContext c) { map.put(c.state(), c); }
            @Override public Optional<Oid4vpAuthorizationRequestContext> consume(String state) { return Optional.ofNullable(map.remove(state)); }
        };
        older.save(context("bank", "s-3", later()));
        assertThat(older.consume("s-3", "other")).isEmpty();
    }

    @Test
    void theResponseEndpointRefusesAStateIssuedForAnotherRelyingParty() {
        var repository = new InMemoryOid4vpAuthorizationRequestRepository();
        repository.save(context("bank", "s-4", later()));
        var converter = new Oid4vpAuthorizationResponseAuthenticationConverter(
                repository, Oid4vpAuthorizationResponseAuthenticationFilter.defaultRequestMatcher(), null);

        var wrong = new MockHttpServletRequest("POST", "/login/oid4vp/direct-post/other");
        wrong.setParameter("state", "s-4");
        wrong.setParameter("vp_token", "{\"employee\":[\"x\"]}");
        assertThatThrownBy(() -> converter.convert(wrong)).isInstanceOf(Oid4vpAuthenticationException.class).hasMessageContaining("state");

        var right = new MockHttpServletRequest("POST", "/login/oid4vp/direct-post/bank");
        right.setParameter("state", "s-4");
        right.setParameter("vp_token", "{\"employee\":[\"x\"]}");
        assertThat(converter.convert(right)).isNotNull();
    }
}
