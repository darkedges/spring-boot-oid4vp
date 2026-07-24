package com.darkedges.oid4vp.mdoc;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link MdocIssuer#issueIssuerSigned} — had no dedicated test before (only exercised transitively,
 * single-namespace, via {@link TestMdocFixtures#buildIssuerSigned}); this covers the multi-namespace case
 * {@link MdocPresentationBuilder}'s namespace-filtering logic actually needs to be tested against, and
 * proves each namespace's digests are independently correct by parsing the result with
 * {@link MdocHeldCredential} (which does not itself verify {@code IssuerAuth}) and separately via a full
 * {@link MdocVerifier} round trip (which does).
 */
class MdocIssuerTest {

    private static final String DOC_TYPE = "org.iso.18013.5.1.mDL";

    @Test
    void issuesAMultiNamespaceCredentialWithCorrectDigestsForEveryElement() throws Exception {
        KeyPair issuerKeys = TestMdocFixtures.generateEcKeyPair();
        KeyPair deviceKeys = TestMdocFixtures.generateEcKeyPair();
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        Map<String, Map<String, String>> claimsByNamespace = new LinkedHashMap<>();
        claimsByNamespace.put("org.iso.18013.5.1", Map.of("given_name", "Jean", "family_name", "Dupont"));
        claimsByNamespace.put("org.iso.18013.5.1.aamva", Map.of("DHS_compliance", "F"));

        byte[] issuerSigned = MdocIssuer.issueIssuerSigned(
                issuerKeys.getPrivate(), List.of(), (ECPublicKey) deviceKeys.getPublic(), DOC_TYPE,
                claimsByNamespace, now, now.plusSeconds(3600));

        MdocHeldCredential credential = MdocHeldCredential.parse(issuerSigned);
        JsonNode claims = credential.claimsView();
        assertThat(claims.get("org.iso.18013.5.1").get("given_name").asText()).isEqualTo("Jean");
        assertThat(claims.get("org.iso.18013.5.1").get("family_name").asText()).isEqualTo("Dupont");
        assertThat(claims.get("org.iso.18013.5.1.aamva").get("DHS_compliance").asText()).isEqualTo("F");

        // digestID sequencing restarts per namespace (0, 1, ...) rather than being globally unique --
        // if valueDigests were keyed/looked-up wrong across namespaces, this would digest-mismatch here.
        String presentation = MdocPresentationBuilder.build(
                credential, com.darkedges.oid4vp.core.dcql.eval.ClaimSelection.MandatoryOnly.INSTANCE,
                deviceKeys.getPrivate(), "x509_hash:test-client", "https://verifier.example.org/response",
                "test-nonce", java.util.Optional.empty());

        com.darkedges.oid4vp.core.dcql.CredentialQuery query =
                com.darkedges.oid4vp.core.dcql.CredentialQuery.builder("mdl", com.darkedges.oid4vp.core.dcql.CredentialFormat.MSO_MDOC)
                        .meta(new com.darkedges.oid4vp.core.dcql.MsoMdocMeta(DOC_TYPE))
                        .build();
        com.darkedges.oid4vp.core.response.IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) ->
                java.util.Optional.of(TestMdocFixtures.publicJwk(issuerKeys.getPublic()));
        var params = new com.darkedges.oid4vp.core.response.PresentationVerificationParams(
                query, "test-nonce", "x509_hash:test-client", "x509_hash:test-client",
                "https://verifier.example.org/response", java.util.Optional.empty(), issuerKeyResolver,
                java.time.Clock.fixed(now.plusSeconds(60), java.time.ZoneOffset.UTC));

        var verified = new MdocVerifier().verify(
                new com.darkedges.oid4vp.core.response.PresentationEntry.StringPresentation(presentation), params);

        JsonNode verifiedClaims = verified.verifiedClaims();
        assertThat(verifiedClaims.get("org.iso.18013.5.1").get("given_name").asText()).isEqualTo("Jean");
        assertThat(verifiedClaims.get("org.iso.18013.5.1.aamva").get("DHS_compliance").asText()).isEqualTo("F");
    }

    @Test
    void deviceKeyOnTheIssuedCredentialMatchesTheSuppliedDeviceKey() throws Exception {
        KeyPair issuerKeys = TestMdocFixtures.generateEcKeyPair();
        KeyPair deviceKeys = TestMdocFixtures.generateEcKeyPair();
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        byte[] issuerSigned = MdocIssuer.issueIssuerSigned(
                issuerKeys.getPrivate(), List.of(), (ECPublicKey) deviceKeys.getPublic(), DOC_TYPE,
                Map.of("org.iso.18013.5.1", Map.of("given_name", "Jean")), now, now.plusSeconds(3600));

        MdocHeldCredential credential = MdocHeldCredential.parse(issuerSigned);
        assertThat(credential.deviceKey().getW().getAffineX())
                .isEqualTo(((ECPublicKey) deviceKeys.getPublic()).getW().getAffineX());
        assertThat(credential.deviceKey().getW().getAffineY())
                .isEqualTo(((ECPublicKey) deviceKeys.getPublic()).getW().getAffineY());
    }
}
