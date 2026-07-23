package com.darkedges.oid4vp.jwtvcjson;

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
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * {@code jwt_vc_json} presentation verifier (OpenID4VP 1.1, format {@code jwt_vc_json} /
 * "JWT-based W3C Verifiable Credentials"): verifies a holder-signed Verifiable Presentation JWT
 * (bound to {@code nonce}/{@code aud}) wrapping exactly one issuer-signed Verifiable Credential JWT.
 *
 * <p>Holder key resolution for the outer VP-JWT and issuer key resolution for the inner VC-JWT both go
 * through the same {@link com.darkedges.oid4vp.core.response.IssuerKeyResolver}, keyed by each JWT's own
 * {@code iss} claim — the resolver doesn't need to know which "role" the identifier plays.
 */
public final class JwtVcJsonVerifier implements PresentationVerifier {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public CredentialFormat format() {
        return CredentialFormat.JWT_VC_JSON;
    }

    @Override
    public VerifiedPresentation verify(PresentationEntry presentation, PresentationVerificationParams params) {
        if (!(presentation instanceof PresentationEntry.StringPresentation(String serialized))) {
            throw new JwtVcJsonVerificationException("jwt_vc_json presentation must be a string, was: " + presentation);
        }

        SignedJWT vpJwt = parse(serialized, "VP-JWT");
        JsonNode vpPayload = decodePayload(vpJwt, "VP-JWT");

        JsonNode holderKey = verifySignature(vpJwt, vpPayload, params, "VP-JWT");
        checkValidityTimes(vpPayload, params, "VP-JWT");
        checkNonceAndAudience(vpPayload, params);

        JsonNode credentials = vpPayload.path("vp").path("verifiableCredential");
        if (!credentials.isArray() || credentials.size() != 1) {
            throw new JwtVcJsonVerificationException(
                    "jwt_vc_json VP-JWT must wrap exactly one Verifiable Credential, found: "
                            + (credentials.isArray() ? credentials.size() : 0));
        }

        SignedJWT vcJwt = parse(credentials.get(0).asText(), "VC-JWT");
        JsonNode vcPayload = decodePayload(vcJwt, "VC-JWT");
        verifySignature(vcJwt, vcPayload, params, "VC-JWT");
        checkValidityTimes(vcPayload, params, "VC-JWT");

        JsonNode verifiedClaims = vcPayload.path("vc");
        if (!verifiedClaims.isObject()) {
            throw new JwtVcJsonVerificationException("VC-JWT payload is missing required \"vc\" object");
        }

        return new VerifiedPresentation(params.query().id(), CredentialFormat.JWT_VC_JSON, verifiedClaims, Optional.of(holderKey));
    }

    private static SignedJWT parse(String compact, String what) {
        try {
            return SignedJWT.parse(compact);
        } catch (ParseException e) {
            throw new JwtVcJsonVerificationException("failed to parse " + what, e);
        }
    }

    private static JsonNode decodePayload(SignedJWT jwt, String what) {
        try {
            return MAPPER.readTree(jwt.getPayload().toBytes());
        } catch (Exception e) {
            throw new JwtVcJsonVerificationException(what + " payload is not valid JSON", e);
        }
    }

    private static JsonNode verifySignature(SignedJWT jwt, JsonNode payload, PresentationVerificationParams params, String what) {
        String issuer = payload.path("iss").asText(null);
        if (issuer == null) {
            throw new JwtVcJsonVerificationException(what + " is missing required \"iss\" claim");
        }
        Optional<String> keyId = Optional.ofNullable(jwt.getHeader().getKeyID());
        List<String> certificateChain = jwt.getHeader().getX509CertChain() == null
                ? List.of()
                : jwt.getHeader().getX509CertChain().stream().map(Object::toString).toList();
        JsonNode jwkNode = params.issuerKeyResolver().resolve(issuer, keyId, certificateChain)
                .orElseThrow(() -> new JwtVcJsonVerificationException("no signing key found for " + what + " issuer \"" + issuer + "\""));

        try {
            ECKey key = ECKey.parse(jwkNode.toString());
            if (!jwt.verify(new ECDSAVerifier(key.toECPublicKey()))) {
                throw new JwtVcJsonVerificationException(what + " signature verification failed");
            }
        } catch (JOSEException | ParseException e) {
            throw new JwtVcJsonVerificationException(what + " signature verification failed", e);
        }
        return jwkNode;
    }

    private static void checkValidityTimes(JsonNode payload, PresentationVerificationParams params, String what) {
        Instant now = params.clock().instant();
        if (payload.hasNonNull("exp")) {
            Instant exp = Instant.ofEpochSecond(payload.get("exp").asLong());
            if (now.isAfter(exp)) {
                throw new JwtVcJsonVerificationException(what + " has expired: exp=" + exp + ", now=" + now);
            }
        }
        if (payload.hasNonNull("nbf")) {
            Instant nbf = Instant.ofEpochSecond(payload.get("nbf").asLong());
            if (now.isBefore(nbf)) {
                throw new JwtVcJsonVerificationException(what + " is not yet valid: nbf=" + nbf + ", now=" + now);
            }
        }
    }

    private static void checkNonceAndAudience(JsonNode vpPayload, PresentationVerificationParams params) {
        String nonce = vpPayload.path("nonce").asText(null);
        if (!params.expectedNonce().equals(nonce)) {
            throw new com.darkedges.oid4vp.core.response.NonceMismatchException(params.expectedNonce(), nonce);
        }
        String aud = vpPayload.path("aud").asText(null);
        if (!params.expectedAudience().equals(aud)) {
            throw new com.darkedges.oid4vp.core.response.AudienceMismatchException(params.expectedAudience(), aud);
        }
    }
}
