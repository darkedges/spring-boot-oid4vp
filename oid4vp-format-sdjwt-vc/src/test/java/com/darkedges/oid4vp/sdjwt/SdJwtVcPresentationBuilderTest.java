package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.ClaimsQuery;
import com.darkedges.oid4vp.core.dcql.eval.ClaimSelection;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Builds a presentation from the {@code sd_jwt_vcld/01} issuance-form fixture and confirms it matches
 * the shape of the spec's own {@code sd_jwt_presentation.txt} (same single disclosure, {@code givenName}),
 * and that it verifies successfully end-to-end via {@link SdJwtVerifier}.
 */
class SdJwtVcPresentationBuilderTest {

    private static SdJwtVcHeldCredential heldCredential() {
        String issuance = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_issuance.txt");
        return SdJwtVcHeldCredential.parse(issuance);
    }

    private static ClaimSelection selectGivenNameOnly() {
        ClaimsQuery givenName = ClaimsQuery.of(null, ClaimsPathPointer.of("ld", "credentialSubject", "givenName"));
        return new ClaimSelection.Selected(List.of(givenName));
    }

    @Test
    void mandatoryOnlySelectionIncludesNoDisclosures() {
        String presentation = SdJwtVcPresentationBuilder.buildWithoutKeyBinding(heldCredential(), ClaimSelection.MandatoryOnly.INSTANCE);

        SdJwt parsed = SdJwtParser.parse(presentation);
        assertThat(parsed.disclosures()).isEmpty();
        assertThat(parsed.keyBindingJwt()).isEmpty();
    }

    @Test
    void selectedGivenNameIncludesExactlyThatOneDisclosure() {
        String presentation = SdJwtVcPresentationBuilder.buildWithoutKeyBinding(heldCredential(), selectGivenNameOnly());

        SdJwt parsed = SdJwtParser.parse(presentation);
        assertThat(parsed.disclosures()).hasSize(1);
        assertThat(parsed.disclosures().get(0).claimName()).contains("givenName");
        assertThat(parsed.disclosures().get(0).claimValue().asText()).isEqualTo("John");
    }

    @Test
    void buildsAFullPresentationThatVerifiesEndToEndRevealingOnlyGivenName() throws Exception {
        SdJwtVcHeldCredential credential = heldCredential();
        String nonce = "test-nonce-123";
        String aud = "https://verifier.example.org";
        Instant iat = Instant.ofEpochSecond(1744743394L);

        java.util.Map<String, Object> settings = FixtureLoader.readYaml("examples/sd_jwt_vcld/settings.yml");
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> keySettings = (java.util.Map<String, Object>) settings.get("key_settings");
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> holderKeyYaml = (java.util.Map<String, Object>) keySettings.get("holder_key");
        com.nimbusds.jose.jwk.ECKey holderKey = new com.nimbusds.jose.jwk.ECKey.Builder(
                com.nimbusds.jose.jwk.Curve.P_256,
                new com.nimbusds.jose.util.Base64URL(holderKeyYaml.get("x").toString()),
                new com.nimbusds.jose.util.Base64URL(holderKeyYaml.get("y").toString()))
                .d(new com.nimbusds.jose.util.Base64URL(holderKeyYaml.get("d").toString()))
                .build();

        String presentation = SdJwtVcPresentationBuilder.buildWithKeyBinding(
                credential, selectGivenNameOnly(), nonce, aud, iat, JWSAlgorithm.ES256, new ECDSASigner(holderKey));

        // Verify end-to-end using the real issuer key from settings.yml, exactly as a Verifier would.
        @SuppressWarnings("unchecked")
        List<java.util.Map<String, Object>> issuerKeys =
                (List<java.util.Map<String, Object>>) keySettings.get("issuer_keys");
        java.util.Map<String, Object> issuerKeyYaml = issuerKeys.get(0);
        com.nimbusds.jose.jwk.ECKey issuerKey = new com.nimbusds.jose.jwk.ECKey.Builder(
                com.nimbusds.jose.jwk.Curve.P_256,
                new com.nimbusds.jose.util.Base64URL(issuerKeyYaml.get("x").toString()),
                new com.nimbusds.jose.util.Base64URL(issuerKeyYaml.get("y").toString()))
                .build();
        com.fasterxml.jackson.databind.JsonNode issuerJwk =
                new com.fasterxml.jackson.databind.ObjectMapper().readTree(issuerKey.toJSONString());

        var query = com.darkedges.oid4vp.core.dcql.CredentialQuery.builder(
                        "my_credential", com.darkedges.oid4vp.core.dcql.CredentialFormat.DC_SD_JWT)
                .meta(new com.darkedges.oid4vp.core.dcql.SdJwtVcMeta(
                        List.of("https://credentials.example.com/example_credential")))
                .build();
        var params = new com.darkedges.oid4vp.core.response.PresentationVerificationParams(
                query, nonce, aud, (issuer, keyId) -> Optional.of(issuerJwk),
                java.time.Clock.fixed(iat, java.time.ZoneOffset.UTC));

        var result = new SdJwtVerifier().verify(
                new com.darkedges.oid4vp.core.response.PresentationEntry.StringPresentation(presentation), params);

        com.fasterxml.jackson.databind.JsonNode credentialSubject = result.verifiedClaims().get("ld").get("credentialSubject");
        assertThat(credentialSubject.get("givenName").asText()).isEqualTo("John");
        assertThat(credentialSubject.has("familyName")).isFalse();
        assertThat(credentialSubject.has("birthDate")).isFalse();
    }
}
