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
import java.util.Optional;

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

    private RequestObjectSigner() {}

    public static SignedJWT sign(
            AuthorizationRequest request, JsonNode signingJwk, JWSAlgorithm alg, Optional<String> walletNonce) {
        ObjectNode claims = AuthorizationRequestWriter.write(request);
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
