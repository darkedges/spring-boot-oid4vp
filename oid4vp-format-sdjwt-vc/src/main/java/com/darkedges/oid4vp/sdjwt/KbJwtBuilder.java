package com.darkedges.oid4vp.sdjwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Builds a Key Binding JWT for an SD-JWT presentation (OpenID4VP 1.1, "IETF SD-JWT VC").
 *
 * <p>Claims ({@code nonce}, {@code aud}, {@code sd_hash}) are added as plain custom claims (not via
 * Nimbus's registered-claim helpers like {@code .audience(...)}) so the serialized JSON matches the
 * spec's examples exactly (a bare string, not a single-element array).
 */
public final class KbJwtBuilder {

    public static final String TYPE = "kb+jwt";

    private KbJwtBuilder() {}

    public static SignedJWT build(
            String sdJwtWithoutKeyBinding,
            String nonce,
            String aud,
            Instant iat,
            JWSAlgorithm alg,
            JWSSigner signer,
            Optional<List<String>> transactionDataHashes,
            Optional<String> transactionDataHashesAlg) {
        String sdHash = computeSdHash(sdJwtWithoutKeyBinding, HashAlgorithms.DEFAULT);

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("aud", aud)
                .issueTime(Date.from(iat))
                .claim("sd_hash", sdHash);
        transactionDataHashes.ifPresent(hashes -> claims.claim("transaction_data_hashes", hashes));
        transactionDataHashesAlg.ifPresent(algName -> claims.claim("transaction_data_hashes_alg", algName));

        JWSHeader header = new JWSHeader.Builder(alg).type(new JOSEObjectType(TYPE)).build();
        SignedJWT jwt = new SignedJWT(header, claims.build());
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new SdJwtVerificationException("failed to sign Key Binding JWT", e);
        }
        return jwt;
    }

    public static SignedJWT build(
            String sdJwtWithoutKeyBinding, String nonce, String aud, Instant iat, JWSAlgorithm alg, JWSSigner signer) {
        return build(sdJwtWithoutKeyBinding, nonce, aud, iat, alg, signer, Optional.empty(), Optional.empty());
    }

    public static String computeSdHash(String sdJwtWithoutKeyBinding, String hashAlg) {
        byte[] hash = HashAlgorithms.newDigest(hashAlg).digest(sdJwtWithoutKeyBinding.getBytes(StandardCharsets.US_ASCII));
        return Base64URL.encode(hash).toString();
    }
}
