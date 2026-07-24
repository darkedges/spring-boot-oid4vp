package com.darkedges.oid4vp.core.request;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The {@code x509_hash} case is exercised against a real certificate and its known-good hash — captured
 * live from an actual OpenID Foundation conformance suite failure report ({@code
 * ExtractAndValidateX509HashClientId}: "Mismatch between Client ID in authorization request and the
 * calculated x509 hash") and independently confirmed via {@code SHA-256(DER)} before this fix, not a
 * fabricated expectation.
 */
class ExpectedAudienceResolverTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String LEAF_CERT_B64 =
            "MIIBxjCCAW2gAwIBAgIUZ0JTAhIzjdHGzXLrW7ZNfPRACQswCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwUb2lkNHZwIGRlbW8gdmVyaWZpZXIwHhcNMjYwNzIzMTA1MDA5WhcNMzYwNzIwMTA1MDA5WjAfMR0wGwYDVQQDDBRvaWQ0dnAgZGVtbyB2ZXJpZmllcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIwbQvTA049bUOug4y0pOfRjKfq/M6t/oZHEExHE9dJabyHhsIg7aVHClW9A9LC7G2fs/9LwkkHyJpaIslYVAsqjgYYwgYMwHQYDVR0OBBYEFGCusyG6OEx8CyZKMUP9VtcYx/t0MB8GA1UdIwQYMBaAFGCusyG6OEx8CyZKMUP9VtcYx/t0MA8GA1UdEwEB/wQFMAMBAf8wMAYDVR0RBCkwJ4IJbG9jYWxob3N0ggh2ZXJpZmllcoIQdmVyaWZ5LmlydmluZy5hdTAKBggqhkjOPQQDAgNHADBEAiBdBAvKMtjEEtZ0QtBTvTj4EfoGeJqWO8mOvqQUvhPPtgIgboD4+MyWPRxPWVfUk5+ZPySwUN8B+DnrnRiocrgxZAc=";
    private static final String EXPECTED_HASH = "x509_hash:lJe9GuAQ-ZLm9UAmWBwH9zCtQr_JqyrYxWeUkz0rz2Y";

    @Test
    void nonX509SanDnsPrefixesPassThroughUnchanged() {
        assertThat(ExpectedAudienceResolver.resolve(
                new ClientIdentifierPrefix.PreRegistered("my-client"), null, "reg"))
                .isEqualTo("my-client");
        assertThat(ExpectedAudienceResolver.resolve(
                new ClientIdentifierPrefix.X509Hash("already-a-hash"), null, "reg"))
                .isEqualTo("x509_hash:already-a-hash");
    }

    @Test
    void x509SanDnsComputesTheSha256ThumbprintOfTheSigningCertLeaf() {
        RequestObjectSigningKeyResolver resolver = registrationId -> Optional.of(signingKeyWithX5c());

        String audience = ExpectedAudienceResolver.resolve(
                new ClientIdentifierPrefix.X509SanDns("verify.irving.au"), resolver, "conformance");

        assertThat(audience).isEqualTo(EXPECTED_HASH);
    }

    @Test
    void x509SanDnsWithoutAResolverFailsClearly() {
        assertThatThrownBy(() -> ExpectedAudienceResolver.resolve(
                new ClientIdentifierPrefix.X509SanDns("verify.irving.au"), null, "conformance"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("requestObjectSigningKeyResolver");
    }

    @Test
    void x509SanDnsWithNoX5cOnTheSigningKeyFailsClearly() {
        RequestObjectSigningKeyResolver resolver = registrationId -> Optional.of(MAPPER.createObjectNode());

        assertThatThrownBy(() -> ExpectedAudienceResolver.resolve(
                new ClientIdentifierPrefix.X509SanDns("verify.irving.au"), resolver, "conformance"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("x5c");
    }

    private static JsonNode signingKeyWithX5c() {
        var node = MAPPER.createObjectNode();
        node.putArray("x5c").add(LEAF_CERT_B64);
        return node;
    }
}
