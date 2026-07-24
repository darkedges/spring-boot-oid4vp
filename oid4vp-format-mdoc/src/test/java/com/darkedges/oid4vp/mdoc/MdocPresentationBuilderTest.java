package com.darkedges.oid4vp.mdoc;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.ClaimsQuery;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.MsoMdocMeta;
import com.darkedges.oid4vp.core.dcql.eval.ClaimSelection;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.PresentationVerificationParams;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link MdocPresentationBuilder} — the Wallet-side counterpart to {@link MdocVerifierTest} — proved by
 * round-tripping through the real {@link MdocVerifier} rather than inspecting the built CBOR directly:
 * this is what actually needs to be true for a real Wallet/Verifier pair to interoperate, and would have
 * caught either of the two live-conformance-only bugs found for this format (wrong SessionTranscript
 * shape, unwrapped DeviceAuthenticationBytes) had it existed before them.
 */
class MdocPresentationBuilderTest {

    private static final String DOC_TYPE = "org.iso.18013.5.1.mDL";
    private static final String NAMESPACE = "org.iso.18013.5.1";
    private static final String CLIENT_ID = "x509_hash:test-client";
    private static final String RESPONSE_URI = "https://verifier.example.org/response";
    private static final String NONCE = "test-nonce";

    private record Fixture(MdocHeldCredential credential, KeyPair issuerKeys, KeyPair deviceKeys, JsonNode encryptionJwk) {}

    private static Fixture issueCredential() throws Exception {
        KeyPair issuerKeys = TestMdocFixtures.generateEcKeyPair();
        KeyPair deviceKeys = TestMdocFixtures.generateEcKeyPair();
        JsonNode encryptionJwk = TestMdocFixtures.publicJwk(TestMdocFixtures.generateEcKeyPair().getPublic());

        byte[] issuerSigned = MdocIssuer.issueIssuerSigned(
                issuerKeys.getPrivate(), List.of(), (ECPublicKey) deviceKeys.getPublic(), DOC_TYPE,
                java.util.Map.of(NAMESPACE, java.util.Map.of("given_name", "Jean", "family_name", "Dupont")),
                Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2027-01-01T00:00:00Z"));

        return new Fixture(MdocHeldCredential.parse(issuerSigned), issuerKeys, deviceKeys, encryptionJwk);
    }

    private static VerifiedPresentation verify(Fixture fixture, String presentation) {
        CredentialQuery query = CredentialQuery.builder("mdl", CredentialFormat.MSO_MDOC)
                .meta(new MsoMdocMeta(DOC_TYPE))
                .build();
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) ->
                Optional.of(TestMdocFixtures.publicJwk(fixture.issuerKeys().getPublic()));
        Instant now = Instant.parse("2026-06-01T00:00:00Z");
        PresentationVerificationParams params = new PresentationVerificationParams(
                query, NONCE, CLIENT_ID, CLIENT_ID, RESPONSE_URI, Optional.of(fixture.encryptionJwk()),
                issuerKeyResolver, Clock.fixed(now, ZoneOffset.UTC));

        return new MdocVerifier().verify(new PresentationEntry.StringPresentation(presentation), params);
    }

    @Test
    void mandatoryOnlySelectionDisclosesEveryHeldElement() throws Exception {
        Fixture fixture = issueCredential();

        String presentation = MdocPresentationBuilder.build(
                fixture.credential(), ClaimSelection.MandatoryOnly.INSTANCE, fixture.deviceKeys().getPrivate(),
                CLIENT_ID, RESPONSE_URI, NONCE, Optional.of(fixture.encryptionJwk()));

        JsonNode claims = verify(fixture, presentation).verifiedClaims().get(NAMESPACE);
        assertThat(claims.get("given_name").asText()).isEqualTo("Jean");
        assertThat(claims.get("family_name").asText()).isEqualTo("Dupont");
    }

    @Test
    void selectedClaimsDiscloseOnlyTheRequestedElement() throws Exception {
        Fixture fixture = issueCredential();
        ClaimSelection selection = new ClaimSelection.Selected(
                List.of(ClaimsQuery.of(null, ClaimsPathPointer.of(NAMESPACE, "given_name"))));

        String presentation = MdocPresentationBuilder.build(
                fixture.credential(), selection, fixture.deviceKeys().getPrivate(),
                CLIENT_ID, RESPONSE_URI, NONCE, Optional.of(fixture.encryptionJwk()));

        JsonNode claims = verify(fixture, presentation).verifiedClaims().get(NAMESPACE);
        assertThat(claims.get("given_name").asText()).isEqualTo("Jean");
        assertThat(claims.has("family_name")).isFalse();
    }

    @Test
    void buildsAVerifiablePresentationWithNoResponseEncryption() throws Exception {
        // Per OpenID4VP 1.1: the OpenID4VPHandover's jwkThumbprint is null (not required) when the
        // response isn't encrypted -- mdoc doesn't inherently require direct_post.jwt.
        Fixture fixture = issueCredential();

        String presentation = MdocPresentationBuilder.build(
                fixture.credential(), ClaimSelection.MandatoryOnly.INSTANCE, fixture.deviceKeys().getPrivate(),
                CLIENT_ID, RESPONSE_URI, NONCE, Optional.empty());

        CredentialQuery query = CredentialQuery.builder("mdl", CredentialFormat.MSO_MDOC)
                .meta(new MsoMdocMeta(DOC_TYPE))
                .build();
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) ->
                Optional.of(TestMdocFixtures.publicJwk(fixture.issuerKeys().getPublic()));
        Instant now = Instant.parse("2026-06-01T00:00:00Z");
        PresentationVerificationParams params = new PresentationVerificationParams(
                query, NONCE, CLIENT_ID, CLIENT_ID, RESPONSE_URI, Optional.empty(),
                issuerKeyResolver, Clock.fixed(now, ZoneOffset.UTC));

        VerifiedPresentation result = new MdocVerifier().verify(new PresentationEntry.StringPresentation(presentation), params);
        assertThat(result.verifiedClaims().get(NAMESPACE).get("given_name").asText()).isEqualTo("Jean");
    }
}
