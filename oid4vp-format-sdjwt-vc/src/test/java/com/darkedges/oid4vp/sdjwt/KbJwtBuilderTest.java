package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Builds a Key Binding JWT against the exact inputs from {@code docs/1.1/examples/sd_jwt_vcld/settings.yml}
 * and {@code kb_jwt_payload.json}.
 *
 * <p>ECDSA signatures are non-deterministic (Nimbus's {@code ECDSASigner} does not use RFC 6979
 * deterministic-k), so byte-for-byte reproduction of {@code kb_jwt_serialized.txt}'s signature is not a
 * valid test target. What <em>is</em> deterministic — the header, the claim values, and {@code sd_hash}
 * (a plain digest) — is asserted exactly instead; independent cross-implementation verification of the
 * fixture's own signature is covered separately by {@link KbJwtVerifierTest}.
 */
class KbJwtBuilderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void buildsHeaderAndPayloadMatchingFixtureExactly() throws Exception {
        SdJwt presentation = SdJwtParser.parse(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt"));
        String sdJwtWithoutKeyBinding = presentation.toStringWithoutKeyBinding();

        JsonNode expectedPayloadForIat = FixtureLoader.readExampleJson("sd_jwt_vcld/01/kb_jwt_payload.json");
        Instant iat = Instant.ofEpochSecond(expectedPayloadForIat.get("iat").asLong());

        SignedJWT kbJwt = KbJwtBuilder.build(
                sdJwtWithoutKeyBinding,
                SdJwtVcldFixture.keyBindingNonce(),
                SdJwtVcldFixture.verifierIdentifier(),
                iat,
                JWSAlgorithm.ES256,
                new ECDSASigner(SdJwtVcldFixture.holderKey()),
                Optional.empty(),
                Optional.empty());

        JsonNode expectedHeader = FixtureLoader.readExampleJson("sd_jwt_vcld/01/kb_jwt_header.json");
        JsonNode actualHeader = MAPPER.readTree(kbJwt.getHeader().toString());
        assertThat(actualHeader).isEqualTo(expectedHeader);

        JsonNode expectedPayload = FixtureLoader.readExampleJson("sd_jwt_vcld/01/kb_jwt_payload.json");
        JsonNode actualPayload = MAPPER.readTree(kbJwt.getJWTClaimsSet().toString());
        assertThat(actualPayload).isEqualTo(expectedPayload);
    }
}
