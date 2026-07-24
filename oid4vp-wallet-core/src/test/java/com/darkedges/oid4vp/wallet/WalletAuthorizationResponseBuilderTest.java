package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.ClaimsQuery;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.dcql.eval.CredentialStore;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.core.response.VpToken;
import com.darkedges.oid4vp.sdjwt.SdJwtVcHeldCredential;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.darkedges.oid4vp.verifier.AuthorizationResponseValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSASigner;
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

/**
 * Full round trip: builds a Wallet response to a DCQL query requesting two selectively-disclosable
 * claims against the {@code sd_jwt_vcld/01} issuance fixture, then verifies the resulting {@code vp_token}
 * on the Verifier side via {@link AuthorizationResponseValidator} — proving the Wallet and Verifier
 * halves of this project actually interoperate, not just each half's own unit tests.
 */
class WalletAuthorizationResponseBuilderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String VCT = "https://credentials.example.com/example_credential";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> sdJwtVcldSettings() {
        return FixtureLoader.readYaml("examples/sd_jwt_vcld/settings.yml");
    }

    @SuppressWarnings("unchecked")
    private static ECKey holderKey() {
        Map<String, Object> keySettings = (Map<String, Object>) sdJwtVcldSettings().get("key_settings");
        Map<String, Object> holderKeyYaml = (Map<String, Object>) keySettings.get("holder_key");
        return new ECKey.Builder(Curve.P_256,
                new Base64URL(holderKeyYaml.get("x").toString()),
                new Base64URL(holderKeyYaml.get("y").toString()))
                .d(new Base64URL(holderKeyYaml.get("d").toString()))
                .build();
    }

    @SuppressWarnings("unchecked")
    private static ECKey issuerKey() {
        Map<String, Object> keySettings = (Map<String, Object>) sdJwtVcldSettings().get("key_settings");
        List<Map<String, Object>> issuerKeys = (List<Map<String, Object>>) keySettings.get("issuer_keys");
        Map<String, Object> issuerKeyYaml = issuerKeys.get(0);
        return new ECKey.Builder(Curve.P_256,
                new Base64URL(issuerKeyYaml.get("x").toString()),
                new Base64URL(issuerKeyYaml.get("y").toString()))
                .build();
    }

    private static HolderKeyResolver holderKeyResolver() {
        return credential -> {
            try {
                return Optional.of(new ECDSASigner(holderKey()));
            } catch (com.nimbusds.jose.JOSEException e) {
                throw new RuntimeException(e);
            }
        };
    }

    private static Clock fixedClock() {
        return Clock.fixed(Instant.ofEpochSecond(1744743394L), ZoneOffset.UTC);
    }

    private static DcqlQuery requestGivenNameAndFamilyName() {
        ClaimsQuery givenName = ClaimsQuery.of("a", ClaimsPathPointer.of("ld", "credentialSubject", "givenName"));
        ClaimsQuery familyName = ClaimsQuery.of("b", ClaimsPathPointer.of("ld", "credentialSubject", "familyName"));
        CredentialQuery credentialQuery = CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of(VCT)))
                .claims(List.of(givenName, familyName))
                .build();
        return DcqlQuery.of(List.of(credentialQuery));
    }

    @Test
    void buildsAResponseThatTheVerifierAcceptsRevealingOnlyTheRequestedClaims() throws Exception {
        HeldCredential credential = SdJwtVcHeldCredential.parse(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_issuance.txt"));
        CredentialStore store = CredentialStore.of(List.of(credential));

        String nonce = "wallet-core-nonce-1";
        String audience = "https://verifier.example.org";
        HolderKeyResolver holderKeyResolver = holderKeyResolver();

        WalletAuthorizationResponseBuilder walletBuilder =
                new WalletAuthorizationResponseBuilder(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVcPresentationBuilderAdapter()));

        WalletAuthorizationResponseResult result = walletBuilder.build(
                requestGivenNameAndFamilyName(), store, new PresentationBuildParams(nonce, audience, audience, "https://verifier.example/response", Optional.empty(), holderKeyResolver, fixedClock()));

        assertThat(result).isInstanceOf(WalletAuthorizationResponseResult.Built.class);
        VpToken vpToken = ((WalletAuthorizationResponseResult.Built) result).vpToken();
        assertThat(vpToken.presentations()).containsOnlyKeys("my_credential");

        // Now hand it to the Verifier side and confirm it validates end-to-end.
        JsonNode issuerJwk = MAPPER.readTree(issuerKey().toJSONString());
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) -> Optional.of(issuerJwk);
        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));

        Map<String, List<VerifiedPresentation>> verified =
                validator.validate(requestGivenNameAndFamilyName(), vpToken, nonce, audience, audience,
                        "https://verifier.example.org/response", Optional.empty(), issuerKeyResolver, fixedClock());

        JsonNode credentialSubject = verified.get("my_credential").get(0).verifiedClaims().get("ld").get("credentialSubject");
        assertThat(credentialSubject.get("givenName").asText()).isEqualTo("John");
        assertThat(credentialSubject.get("familyName").asText()).isEqualTo("Doe");
        assertThat(credentialSubject.has("birthDate")).isFalse();
    }

    @Test
    void declinesWhenNoCredentialMatchesTheRequestedType() {
        HeldCredential credential = SdJwtVcHeldCredential.parse(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_issuance.txt"));
        CredentialStore store = CredentialStore.of(List.of(credential));

        CredentialQuery unmatchable = CredentialQuery.builder("wanted", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://credentials.example.com/some_other_type")))
                .build();
        DcqlQuery query = DcqlQuery.of(List.of(unmatchable));

        WalletAuthorizationResponseBuilder walletBuilder =
                new WalletAuthorizationResponseBuilder(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVcPresentationBuilderAdapter()));
        HolderKeyResolver holderKeyResolver = holderKeyResolver();

        WalletAuthorizationResponseResult result = walletBuilder.build(
                query, store, new PresentationBuildParams("n", "aud", "aud", "https://verifier.example/response", Optional.empty(), holderKeyResolver, fixedClock()));

        assertThat(result).isInstanceOf(WalletAuthorizationResponseResult.Declined.class);
    }
}
