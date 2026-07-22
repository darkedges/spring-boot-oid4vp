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
 */
public final class RequestObjectSigner {

    public static final String TYPE = "oauth-authz-req+jwt";

    private RequestObjectSigner() {}

    public static SignedJWT sign(
            AuthorizationRequest request, JsonNode signingJwk, JWSAlgorithm alg, Optional<String> walletNonce) {
        ObjectNode claims = AuthorizationRequestWriter.write(request);
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
