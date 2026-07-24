package com.darkedges.oid4vp.verifier;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.CredentialSetQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.Oid4vpException;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.core.response.VpToken;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Exercises {@link AuthorizationResponseValidator} end-to-end against the real
 * {@code sd_jwt_vcld/01} presentation fixture, going through {@link VpToken} JSON just as a
 * {@code direct_post} body would be parsed.
 */
class AuthorizationResponseValidatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String VCT = "https://credentials.example.com/example_credential";

    private static CredentialQuery credentialQuery(String id) {
        return CredentialQuery.builder(id, CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of(VCT)))
                .build();
    }

    // docs/1.1/examples/sd_jwt_vcld/settings.yml is the single source of truth for these deterministic
    // test-vector keys/identifiers; re-read directly here since test helpers aren't shared across
    // module test-jars.
    @SuppressWarnings("unchecked")
    private static Map<String, Object> sdJwtVcldSettings() {
        return FixtureLoader.readYaml("examples/sd_jwt_vcld/settings.yml");
    }

    private static String verifierIdentifier() {
        return ((Map<String, Object>) sdJwtVcldSettings().get("identifiers")).get("verifier").toString();
    }

    private static String keyBindingNonce() {
        return sdJwtVcldSettings().get("key_binding_nonce").toString();
    }

    private static IssuerKeyResolver issuerKeyResolver() throws Exception {
        Map<String, Object> keySettings = (Map<String, Object>) sdJwtVcldSettings().get("key_settings");
        Map<String, Object> issuerKeyYaml = ((List<Map<String, Object>>) keySettings.get("issuer_keys")).get(0);
        ECKey issuerKey = new ECKey.Builder(Curve.P_256,
                new Base64URL(issuerKeyYaml.get("x").toString()),
                new Base64URL(issuerKeyYaml.get("y").toString()))
                .build();
        JsonNode jwk = MAPPER.readTree(issuerKey.toJSONString());
        return (issuer, keyId, certificateChain) -> Optional.of(jwk);
    }

    private static Clock fixedClock() {
        return Clock.fixed(Instant.ofEpochSecond(1744743394L), ZoneOffset.UTC);
    }

    @Test
    void validatesASingleCredentialResponse() throws Exception {
        DcqlQuery query = DcqlQuery.of(List.of(credentialQuery("my_credential")));
        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        VpToken vpToken = new VpToken(Map.of("my_credential", List.of(new PresentationEntry.StringPresentation(presentation))));

        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));

        Map<String, List<VerifiedPresentation>> result = validator.validate(
                query, vpToken,
                keyBindingNonce(),
                verifierIdentifier(),
                verifierIdentifier(), "https://verifier.example.org/response", Optional.empty(),
                issuerKeyResolver(), fixedClock());

        assertThat(result).containsOnlyKeys("my_credential");
        JsonNode claims = result.get("my_credential").get(0).verifiedClaims();
        assertThat(claims.get("ld").get("credentialSubject").get("givenName").asText()).isEqualTo("John");
    }

    @Test
    void rejectsResponseMissingARequiredCredentialQuery() {
        DcqlQuery query = DcqlQuery.of(List.of(credentialQuery("my_credential"), credentialQuery("other_credential")));
        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        VpToken vpToken = new VpToken(Map.of("my_credential", List.of(new PresentationEntry.StringPresentation(presentation))));

        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));

        assertThatThrownBy(() -> validator.validate(
                query, vpToken, "nonce", "aud", "aud", "https://verifier.example.org/response", Optional.empty(),
                (issuer, keyId, certificateChain) -> Optional.empty(), fixedClock()))
                .isInstanceOf(Oid4vpException.class);
    }

    @Test
    void rejectsWhenNoVerifierIsRegisteredForTheFormat() {
        DcqlQuery query = DcqlQuery.of(List.of(credentialQuery("my_credential")));
        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        VpToken vpToken = new VpToken(Map.of("my_credential", List.of(new PresentationEntry.StringPresentation(presentation))));

        AuthorizationResponseValidator validator = new AuthorizationResponseValidator(Map.of());

        assertThatThrownBy(() -> validator.validate(
                query, vpToken, "nonce", "aud", "aud", "https://verifier.example.org/response", Optional.empty(),
                (issuer, keyId, certificateChain) -> Optional.empty(), fixedClock()))
                .isInstanceOf(Oid4vpException.class)
                .satisfies(e -> assertThat(((Oid4vpException) e).errorCode())
                        .isEqualTo(com.darkedges.oid4vp.core.response.Oid4vpErrorCode.VP_FORMATS_NOT_SUPPORTED));
    }

    @Test
    void satisfiesCredentialSetsWithFirstMatchingOption() throws Exception {
        DcqlQuery query = new DcqlQuery(
                List.of(credentialQuery("option_a"), credentialQuery("option_b")),
                Optional.of(List.of(CredentialSetQuery.required(List.of(List.of("option_a"), List.of("option_b"))))));
        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        VpToken vpToken = new VpToken(Map.of("option_b", List.of(new PresentationEntry.StringPresentation(presentation))));

        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));

        Map<String, List<VerifiedPresentation>> result = validator.validate(
                query, vpToken,
                keyBindingNonce(),
                verifierIdentifier(),
                verifierIdentifier(), "https://verifier.example.org/response", Optional.empty(),
                issuerKeyResolver(), fixedClock());

        assertThat(result).containsOnlyKeys("option_b");
    }
}
