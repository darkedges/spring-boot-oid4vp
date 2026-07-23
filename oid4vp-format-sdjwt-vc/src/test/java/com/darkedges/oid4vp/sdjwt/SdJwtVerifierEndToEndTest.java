package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.PresentationVerificationParams;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The flagship end-to-end test: feeds {@code sd_jwt_vcld/01/sd_jwt_presentation.txt} alone into
 * {@link SdJwtVerifier} (no access to the other two withheld disclosures) with the issuer/holder keys
 * and identifiers from {@code settings.yml}, and asserts full verification succeeds while only
 * {@code givenName} is reconstructable — matching {@code specification.yml}'s
 * {@code holder_disclosed_claims}.
 */
class SdJwtVerifierEndToEndTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void verifiesThePresentationAndRevealsOnlyTheDisclosedClaim() throws Exception {
        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");

        CredentialQuery query = CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://credentials.example.com/example_credential")))
                .build();

        JsonNode issuerPublicJwk = MAPPER.readTree(
                SdJwtVcldFixture.issuerKey().toPublicJWK().toJSONString());
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) -> Optional.of(issuerPublicJwk);

        // A fixed point in time within [iat, exp] of the fixture (also matching the KB-JWT's own iat),
        // so validity checks are reproducible rather than depending on the wall clock.
        Clock clock = Clock.fixed(Instant.ofEpochSecond(1744743394L), ZoneOffset.UTC);

        PresentationVerificationParams params = new PresentationVerificationParams(
                query,
                SdJwtVcldFixture.keyBindingNonce(),
                SdJwtVcldFixture.verifierIdentifier(),
                issuerKeyResolver,
                clock);

        VerifiedPresentation result = new SdJwtVerifier().verify(new PresentationEntry.StringPresentation(presentation), params);

        assertThat(result.credentialQueryId()).isEqualTo("my_credential");
        assertThat(result.format()).isEqualTo(CredentialFormat.DC_SD_JWT);
        assertThat(result.holderKeyConfirmed()).isPresent();

        JsonNode credentialSubject = result.verifiedClaims().get("ld").get("credentialSubject");
        assertThat(credentialSubject.get("givenName").asText()).isEqualTo("John");
        assertThat(credentialSubject.has("familyName")).isFalse();
        assertThat(credentialSubject.has("birthDate")).isFalse();
        assertThat(result.verifiedClaims().has("_sd")).isFalse();
        assertThat(result.verifiedClaims().has("_sd_alg")).isFalse();
    }

    @Test
    void rejectsWhenNonceDoesNotMatch() {
        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        CredentialQuery query = CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://credentials.example.com/example_credential")))
                .build();
        JsonNode issuerPublicJwk = jsonOrThrow();
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) -> Optional.of(issuerPublicJwk);
        Clock clock = Clock.fixed(Instant.ofEpochSecond(1744743394L), ZoneOffset.UTC);

        PresentationVerificationParams params = new PresentationVerificationParams(
                query, "wrong-nonce", SdJwtVcldFixture.verifierIdentifier(), issuerKeyResolver, clock);

        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> new SdJwtVerifier().verify(new PresentationEntry.StringPresentation(presentation), params))
                .isInstanceOf(com.darkedges.oid4vp.core.response.NonceMismatchException.class);
    }

    private static JsonNode jsonOrThrow() {
        try {
            return MAPPER.readTree(SdJwtVcldFixture.issuerKey().toPublicJWK().toJSONString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
