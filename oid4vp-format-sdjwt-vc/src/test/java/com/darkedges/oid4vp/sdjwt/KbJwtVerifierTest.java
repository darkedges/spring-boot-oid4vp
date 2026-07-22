package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.SignedJWT;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

class KbJwtVerifierTest {

    @Test
    void selfVerifiesAFreshlyBuiltKeyBindingJwt() throws Exception {
        SdJwt presentation = SdJwtParser.parse(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt"));
        String sdJwtWithoutKeyBinding = presentation.toStringWithoutKeyBinding();
        Instant iat = SdJwtVcldFixture.iat();

        SignedJWT kbJwt = KbJwtBuilder.build(
                sdJwtWithoutKeyBinding,
                SdJwtVcldFixture.keyBindingNonce(),
                SdJwtVcldFixture.verifierIdentifier(),
                iat,
                JWSAlgorithm.ES256,
                new ECDSASigner(SdJwtVcldFixture.holderKey()),
                Optional.empty(),
                Optional.empty());
        String sdHash = KbJwtBuilder.computeSdHash(sdJwtWithoutKeyBinding, "sha-256");

        Clock fixedClock = Clock.fixed(iat, ZoneOffset.UTC);

        Assertions.assertThatCode(() -> KbJwtVerifier.verify(
                        kbJwt,
                        SdJwtVcldFixture.holderKey(),
                        SdJwtVcldFixture.keyBindingNonce(),
                        SdJwtVcldFixture.verifierIdentifier(),
                        sdHash,
                        fixedClock,
                        Duration.ZERO))
                .doesNotThrowAnyException();
    }

    @Test
    void independentlyVerifiesThePreBuiltFixtureKeyBindingJwt() throws Exception {
        // Proves interop with the external sd-jwt-python reference implementation that generated this
        // fixture, without requiring identical signature bytes (ECDSA is non-deterministic).
        String serialized = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/kb_jwt_serialized.txt");
        SignedJWT kbJwt = SignedJWT.parse(serialized);

        JsonNode expectedPayload = FixtureLoader.readExampleJson("sd_jwt_vcld/01/kb_jwt_payload.json");
        String expectedSdHash = expectedPayload.get("sd_hash").asText();
        Instant iat = Instant.ofEpochSecond(expectedPayload.get("iat").asLong());
        Clock fixedClock = Clock.fixed(iat, ZoneOffset.UTC);

        Assertions.assertThatCode(() -> KbJwtVerifier.verify(
                        kbJwt,
                        SdJwtVcldFixture.holderKey(),
                        SdJwtVcldFixture.keyBindingNonce(),
                        SdJwtVcldFixture.verifierIdentifier(),
                        expectedSdHash,
                        fixedClock,
                        Duration.ZERO))
                .doesNotThrowAnyException();
    }
}
