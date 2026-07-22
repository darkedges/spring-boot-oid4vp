package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Reconstructs claims from {@code sd_jwt_vcld/01/sd_jwt_payload.json} plus its disclosures and asserts
 * the result equals {@code verified_contents.json} exactly (the fixture's own "post-verification" oracle).
 */
class SdJwtDigestVerificationTest {

    @Test
    void reconstructsOnlyTheDisclosedClaimAndMatchesTheFixtureOracleExactly() {
        JsonNode payload = FixtureLoader.readExampleJson("sd_jwt_vcld/01/sd_jwt_payload.json");
        // Only the single disclosure actually included in the presentation (givenName), per
        // specification.yml's holder_disclosed_claims.
        SdJwt presentation = SdJwtParser.parse(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt"));

        JsonNode reconstructed = SdJwtDigestVerifier.verify(payload, presentation.disclosures());

        JsonNode expected = FixtureLoader.readExampleJson("sd_jwt_vcld/01/verified_contents.json");
        assertThat(reconstructed).isEqualTo(expected);
    }

    @Test
    void reconstructsAllThreeClaimsWhenAllDisclosuresAreGiven() {
        JsonNode payload = FixtureLoader.readExampleJson("sd_jwt_vcld/01/sd_jwt_payload.json");
        SdJwt issuance = SdJwtParser.parse(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_issuance.txt"));

        JsonNode reconstructed = SdJwtDigestVerifier.verify(payload, issuance.disclosures());

        JsonNode credentialSubject = reconstructed.get("ld").get("credentialSubject");
        assertThat(credentialSubject.get("givenName").asText()).isEqualTo("John");
        assertThat(credentialSubject.get("familyName").asText()).isEqualTo("Doe");
        assertThat(credentialSubject.get("birthDate").asText()).isEqualTo("1978-07-17");
        assertThat(reconstructed.has("_sd")).isFalse();
        assertThat(reconstructed.has("_sd_alg")).isFalse();
    }

    @Test
    void failsWhenADisclosureCannotBeMatchedToAnyDigest() {
        JsonNode payload = FixtureLoader.readExampleJson("sd_jwt_vcld/01/sd_jwt_payload.json");
        Disclosure bogus = Disclosure.createObjectProperty(
                "unrelated-salt", "unrelated_claim", com.fasterxml.jackson.databind.node.TextNode.valueOf("x"));

        assertThatThrownBy(() -> SdJwtDigestVerifier.verify(payload, List.of(bogus)))
                .isInstanceOf(SdJwtVerificationException.class);
    }
}
