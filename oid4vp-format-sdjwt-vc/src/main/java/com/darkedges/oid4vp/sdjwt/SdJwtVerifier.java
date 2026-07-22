package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.PresentationVerificationParams;
import com.darkedges.oid4vp.core.response.PresentationVerifier;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * The top-level {@code dc+sd-jwt} presentation verifier: parses an SD-JWT(+KB) presentation string,
 * verifies the Issuer's signature, checks validity times, digest-verifies the disclosed claims, and (if
 * required by the Credential Query) verifies the Key Binding JWT's binding to this transaction.
 */
public final class SdJwtVerifier implements PresentationVerifier {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration KB_JWT_CLOCK_SKEW = Duration.ofMinutes(5);

    @Override
    public CredentialFormat format() {
        return CredentialFormat.DC_SD_JWT;
    }

    @Override
    public VerifiedPresentation verify(PresentationEntry presentation, PresentationVerificationParams params) {
        if (!(presentation instanceof PresentationEntry.StringPresentation(String serialized))) {
            throw new SdJwtVerificationException("dc+sd-jwt presentation must be a string, was: " + presentation);
        }

        SdJwt sdJwt = SdJwtParser.parse(serialized);
        JsonNode rawPayload = decodePayload(sdJwt.issuerSignedJwt());

        verifyIssuerSignature(sdJwt.issuerSignedJwt(), rawPayload, params);
        checkValidityTimes(rawPayload, params);

        JsonNode verifiedClaims = SdJwtDigestVerifier.verify(rawPayload, sdJwt.disclosures());

        Optional<JsonNode> holderKeyConfirmed = Optional.empty();
        if (params.query().requireCryptographicHolderBinding()) {
            holderKeyConfirmed = Optional.of(verifyKeyBinding(sdJwt, rawPayload, params));
        }

        return new VerifiedPresentation(params.query().id(), CredentialFormat.DC_SD_JWT, verifiedClaims, holderKeyConfirmed);
    }

    private static JsonNode decodePayload(SignedJWT issuerSignedJwt) {
        try {
            return MAPPER.readTree(issuerSignedJwt.getPayload().toBytes());
        } catch (Exception e) {
            throw new SdJwtVerificationException("SD-JWT issuer-signed JWT payload is not valid JSON", e);
        }
    }

    private static void verifyIssuerSignature(SignedJWT issuerSignedJwt, JsonNode rawPayload, PresentationVerificationParams params) {
        String issuer = rawPayload.path("iss").asText(null);
        if (issuer == null) {
            throw new SdJwtVerificationException("SD-JWT is missing required \"iss\" claim");
        }
        Optional<String> keyId = Optional.ofNullable(issuerSignedJwt.getHeader().getKeyID());
        JsonNode jwkNode = params.issuerKeyResolver().resolve(issuer, keyId)
                .orElseThrow(() -> new SdJwtVerificationException("no issuer key found for issuer \"" + issuer + "\""));

        try {
            ECKey issuerKey = ECKey.parse(jwkNode.toString());
            if (!issuerSignedJwt.verify(new ECDSAVerifier(issuerKey.toECPublicKey()))) {
                throw new SdJwtVerificationException("SD-JWT issuer signature verification failed");
            }
        } catch (JOSEException | java.text.ParseException e) {
            throw new SdJwtVerificationException("SD-JWT issuer signature verification failed", e);
        }
    }

    private static void checkValidityTimes(JsonNode rawPayload, PresentationVerificationParams params) {
        Instant now = params.clock().instant();
        if (rawPayload.hasNonNull("exp")) {
            Instant exp = Instant.ofEpochSecond(rawPayload.get("exp").asLong());
            if (now.isAfter(exp)) {
                throw new SdJwtVerificationException("SD-JWT has expired: exp=" + exp + ", now=" + now);
            }
        }
        if (rawPayload.hasNonNull("nbf")) {
            Instant nbf = Instant.ofEpochSecond(rawPayload.get("nbf").asLong());
            if (now.isBefore(nbf)) {
                throw new SdJwtVerificationException("SD-JWT is not yet valid: nbf=" + nbf + ", now=" + now);
            }
        }
    }

    private static JsonNode verifyKeyBinding(SdJwt sdJwt, JsonNode rawPayload, PresentationVerificationParams params) {
        SignedJWT keyBindingJwt = sdJwt.keyBindingJwt()
                .orElseThrow(() -> new SdJwtVerificationException(
                        "Credential Query requires Cryptographic Holder Binding but no Key Binding JWT was presented"));

        JsonNode cnfJwk = rawPayload.path("cnf").path("jwk");
        if (!cnfJwk.isObject()) {
            throw new SdJwtVerificationException("SD-JWT has no \"cnf\".\"jwk\" but Cryptographic Holder Binding was required");
        }

        ECKey holderKey;
        try {
            holderKey = ECKey.parse(cnfJwk.toString());
        } catch (java.text.ParseException e) {
            throw new SdJwtVerificationException("SD-JWT \"cnf\".\"jwk\" is not a valid EC JWK", e);
        }

        String expectedSdHash = KbJwtBuilder.computeSdHash(sdJwt.toStringWithoutKeyBinding(), HashAlgorithms.DEFAULT);
        KbJwtVerifier.verify(
                keyBindingJwt, holderKey, params.expectedNonce(), params.expectedAudience(), expectedSdHash,
                params.clock(), KB_JWT_CLOCK_SKEW);

        return cnfJwk;
    }
}
