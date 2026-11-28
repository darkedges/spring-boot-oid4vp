package com.darkedges.oid4vp.verifier.request;

import com.darkedges.oid4vp.core.request.AuthorizationRequest;
import com.darkedges.oid4vp.core.request.AuthorizationRequestWriter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Signs an {@link AuthorizationRequest} as a JWT-Secured Authorization Request (JAR, RFC9101) per
 * OpenID4VP 1.1: header {@code typ} MUST be {@code oauth-authz-req+jwt}; the payload is every
 * Authorization Request parameter as a top-level claim.
 *
 * <p>{@code wallet_nonce}, when present, is the value the Wallet sent when fetching the Request Object
 * via {@code request_uri_method=post}; OpenID4VP 1.1 requires it be echoed back inside the signed
 * Request Object.
 *
 * <p>{@code aud} is always {@code "https://self-issued.me/v2"} — OpenID4VP 1.1 §5.8 requires {@code aud}
 * to equal the issuer claim only under Dynamic Discovery (resolving a Wallet's own issuer metadata), which
 * this project doesn't implement; every registration here is Static Discovery, for which that symbolic
 * constant is the spec-mandated value.
 *
 * <p>When {@code signingJwk} carries an {@code x5c} certificate chain, it's copied into the JWS header —
 * required by the {@code x509_san_dns}/{@code x509_hash} Client Identifier Prefixes, where the Wallet
 * verifies the signature directly against the leaf certificate in the request itself rather than
 * resolving a key some other way.
 */
public final class RequestObjectSigner {

    public static final String TYPE = "oauth-authz-req+jwt";
    private static final String STATIC_DISCOVERY_AUDIENCE = "https://self-issued.me/v2";

    /** Parameters an application can't add: the protocol's own, which come from the {@link AuthorizationRequest}, and JWT claims. */
    private static final Set<String> RESERVED = Set.of(
            "response_type", "client_id", "client_id_scheme", "response_mode", "response_uri", "redirect_uri", "dcql_query",
            "presentation_definition", "presentation_definition_uri", "scope", "state", "nonce", "client_metadata",
            "client_metadata_uri", "request", "request_uri", "request_uri_method", "transaction_data", "verifier_info",
            "verifier_attestations", "code_challenge", "code_challenge_method", "wallet_nonce", "expected_origins",
            "iss", "sub", "aud", "exp", "iat", "nbf", "jti");

    private RequestObjectSigner() {}

    /** Whether {@code name} is a parameter an application may not add to a request object. */
    public static boolean isReserved(String name) {
        return RESERVED.contains(name);
    }

    public static SignedJWT sign(
            AuthorizationRequest request, JsonNode signingJwk, JWSAlgorithm alg, Optional<String> walletNonce) {
        return sign(request, signingJwk, alg, walletNonce, Map.of());
    }

    /**
     * As {@link #sign(AuthorizationRequest, JsonNode, JWSAlgorithm, Optional)}, with the application's own parameters as further string
     * claims.
     *
     * @throws IllegalArgumentException for a {@linkplain #isReserved reserved} name
     */
    public static SignedJWT sign(
            AuthorizationRequest request, JsonNode signingJwk, JWSAlgorithm alg, Optional<String> walletNonce,
            Map<String, String> parameters) {
        ObjectNode claims = AuthorizationRequestWriter.write(request);
        parameters.forEach((name, value) -> {
            if (isReserved(name)) throw new IllegalArgumentException("not a parameter an application can add: " + name);
            claims.put(name, value);
        });
        claims.put("aud", STATIC_DISCOVERY_AUDIENCE);
        walletNonce.ifPresent(nonce -> claims.put("wallet_nonce", nonce));

        ECKey key;
        try {
            key = ECKey.parse(signingJwk.toString());
        } catch (ParseException e) {
            throw new IllegalStateException("configured request object signing key is not a valid EC JWK", e);
        }

        JWSHeader.Builder header = new JWSHeader.Builder(alg).type(new JOSEObjectType(TYPE));
        if (key.getKeyID() != null) {
            header.keyID(key.getKeyID());
        }
        if (key.getX509CertChain() != null && !key.getX509CertChain().isEmpty()) {
            header.x509CertChain(key.getX509CertChain());
        }

        JWTClaimsSet claimsSet;
        try {
            claimsSet = JWTClaimsSet.parse(claims.toString());
        } catch (ParseException e) {
            throw new IllegalStateException("failed to build claims for the request object", e);
        }

        SignedJWT jwt = new SignedJWT(header.build(), claimsSet);
        try {
            jwt.sign(new ECDSASigner(key));
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to sign the request object", e);
        }
        return jwt;
    }
}
