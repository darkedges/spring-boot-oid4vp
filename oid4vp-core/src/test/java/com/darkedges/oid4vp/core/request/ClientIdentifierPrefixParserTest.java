package com.darkedges.oid4vp.core.request;

import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cases sourced directly from OpenID4VP 1.1, "Client Identifier Prefix and Verifier Metadata Management"
 * > "Defined Client Identifier Prefixes" (the non-normative example for each prefix), plus the
 * {@code client_id} used in {@code docs/1.1/examples/request/request_object_client_id_did.json}.
 */
class ClientIdentifierPrefixParserTest {

    @Test
    void parsesRedirectUriPrefix() {
        ClientIdentifierPrefix parsed = ClientIdentifierPrefixParser.parse("redirect_uri:https://client.example.org/cb");

        assertThat(parsed).isEqualTo(new ClientIdentifierPrefix.RedirectUri("https://client.example.org/cb"));
        assertThat(parsed.fullClientId()).isEqualTo("redirect_uri:https://client.example.org/cb");
    }

    @Test
    void parsesOpenidFederationPrefix() {
        ClientIdentifierPrefix parsed =
                ClientIdentifierPrefixParser.parse("openid_federation:https://federation-verifier.example.com");

        assertThat(parsed)
                .isEqualTo(new ClientIdentifierPrefix.OpenidFederation("https://federation-verifier.example.com"));
    }

    @Test
    void parsesDecentralizedIdentifierPrefixPreservingInnerColons() {
        ClientIdentifierPrefix parsed = ClientIdentifierPrefixParser.parse("decentralized_identifier:did:example:123");

        assertThat(parsed).isEqualTo(new ClientIdentifierPrefix.DecentralizedIdentifier("did:example:123"));
    }

    @Test
    void parsesClientIdFromRequestObjectFixture() {
        // This fixture's dcql_query value is a literal "{ ... }" placeholder (see the source markdown),
        // so it isn't valid standalone JSON; extract client_id from the raw text instead of parsing it.
        String raw = FixtureLoader.readExample("request/request_object_client_id_did.json");
        java.util.regex.Matcher matcher =
                java.util.regex.Pattern.compile("\"client_id\"\\s*:\\s*\"([^\"]+)\"").matcher(raw);
        assertThat(matcher.find()).as("client_id present in fixture").isTrue();

        ClientIdentifierPrefix parsed = ClientIdentifierPrefixParser.parse(matcher.group(1));

        assertThat(parsed).isEqualTo(new ClientIdentifierPrefix.DecentralizedIdentifier("did:example:123"));
    }

    @Test
    void parsesVerifierAttestationPrefix() {
        ClientIdentifierPrefix parsed = ClientIdentifierPrefixParser.parse("verifier_attestation:verifier.example");

        assertThat(parsed).isEqualTo(new ClientIdentifierPrefix.VerifierAttestation("verifier.example"));
    }

    @Test
    void parsesX509SanDnsPrefix() {
        ClientIdentifierPrefix parsed = ClientIdentifierPrefixParser.parse("x509_san_dns:client.example.org");

        assertThat(parsed).isEqualTo(new ClientIdentifierPrefix.X509SanDns("client.example.org"));
    }

    @Test
    void parsesX509HashPrefix() {
        ClientIdentifierPrefix parsed =
                ClientIdentifierPrefixParser.parse("x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk");

        assertThat(parsed).isEqualTo(new ClientIdentifierPrefix.X509Hash("Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk"));
    }

    @Test
    void parsesReservedOriginPrefixSyntactically() {
        // Syntax parsing only; rejecting this if it arrives in an actual Verifier request is a caller concern.
        ClientIdentifierPrefix parsed = ClientIdentifierPrefixParser.parse("origin:https://verifier.example.com");

        assertThat(parsed).isEqualTo(new ClientIdentifierPrefix.Origin("https://verifier.example.com"));
    }

    @Test
    void fallsBackToPreRegisteredWhenNoColonPresent() {
        ClientIdentifierPrefix parsed = ClientIdentifierPrefixParser.parse("example-client");

        assertThat(parsed).isEqualTo(new ClientIdentifierPrefix.PreRegistered("example-client"));
        assertThat(parsed.fullClientId()).isEqualTo("example-client");
    }

    @Test
    void fallsBackToPreRegisteredUsingWholeStringWhenPrefixTokenIsUnrecognized() {
        ClientIdentifierPrefix parsed = ClientIdentifierPrefixParser.parse("not_a_real_prefix:something");

        assertThat(parsed).isEqualTo(new ClientIdentifierPrefix.PreRegistered("not_a_real_prefix:something"));
    }
}
