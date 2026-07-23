package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** {@code codeVerifier} is a new optional field (Authorization Code Grant / PKCE) — confirms it round-trips
 * and that the pre-existing shorter-arity constructors (used throughout the codebase before this field
 * existed) still default it to empty without needing every call site updated. */
class Oid4vpAuthorizationRequestContextTest {

    private static DcqlQuery sampleDcqlQuery() {
        return DcqlQuery.of(List.of(CredentialQuery.builder("pid", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://credentials.example.com/identity_credential")))
                .build()));
    }

    @Test
    void codeVerifierRoundTripsWhenSuppliedToTheCanonicalConstructor() {
        Oid4vpAuthorizationRequestContext context = new Oid4vpAuthorizationRequestContext(
                "demo", "state-1", "nonce-1", new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                sampleDcqlQuery(), URI.create("https://verifier.example.org/response"),
                Instant.now().plusSeconds(300), Optional.empty(), Optional.of("verifier-value"));

        assertThat(context.codeVerifier()).contains("verifier-value");
    }

    @Test
    void olderShorterArityConstructorsDefaultCodeVerifierToEmpty() {
        Oid4vpAuthorizationRequestContext sevenArg = new Oid4vpAuthorizationRequestContext(
                "demo", "state-2", "nonce-2", new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                sampleDcqlQuery(), URI.create("https://verifier.example.org/response"), Instant.now().plusSeconds(300));
        Oid4vpAuthorizationRequestContext eightArg = new Oid4vpAuthorizationRequestContext(
                "demo", "state-3", "nonce-3", new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                sampleDcqlQuery(), URI.create("https://verifier.example.org/response"), Instant.now().plusSeconds(300),
                Optional.of("txn-1"));

        assertThat(sevenArg.codeVerifier()).isEmpty();
        assertThat(eightArg.codeVerifier()).isEmpty();
        assertThat(eightArg.transactionId()).contains("txn-1");
    }
}
