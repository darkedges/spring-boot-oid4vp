package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.core.response.AudienceMismatchException;
import com.darkedges.oid4vp.core.response.NonceMismatchException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/** Verifies a Key Binding JWT's signature, its binding to the current transaction (nonce/audience) and
 * to a specific SD-JWT presentation ({@code sd_hash}), and that {@code iat} is fresh — within
 * {@code allowedClockSkew} either side of now, not just not-in-the-future. A stale Key Binding JWT (e.g.
 * one reused from a year-old presentation) is exactly the kind of replay this claim exists to prevent. */
public final class KbJwtVerifier {

    private KbJwtVerifier() {}

    public static void verify(
            SignedJWT kbJwt,
            ECKey holderKey,
            String expectedNonce,
            String expectedAud,
            String expectedSdHash,
            Clock clock,
            Duration allowedClockSkew) {
        try {
            if (!kbJwt.verify(new ECDSAVerifier(holderKey.toECPublicKey()))) {
                throw new SdJwtVerificationException("Key Binding JWT signature verification failed");
            }
        } catch (JOSEException e) {
            throw new SdJwtVerificationException("Key Binding JWT signature verification failed", e);
        }

        JWTClaimsSet claims;
        try {
            claims = kbJwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new SdJwtVerificationException("Key Binding JWT claims could not be parsed", e);
        }

        String nonce = getStringClaim(claims, "nonce");
        if (!expectedNonce.equals(nonce)) {
            throw new NonceMismatchException(expectedNonce, nonce);
        }

        // "aud" is a registered JWT claim and may legitimately be serialized as either a bare string or
        // a single-element array; getAudience() normalizes both forms to a List<String>.
        List<String> aud = claims.getAudience();
        if (aud == null || !aud.contains(expectedAud)) {
            throw new AudienceMismatchException(expectedAud, String.valueOf(aud));
        }

        String sdHash = getStringClaim(claims, "sd_hash");
        if (!expectedSdHash.equals(sdHash)) {
            throw new SdJwtVerificationException(
                    "sd_hash mismatch: Key Binding JWT is not bound to the presented SD-JWT (expected \""
                            + expectedSdHash + "\", was \"" + sdHash + "\")");
        }

        Instant iat = claims.getIssueTime() == null ? null : claims.getIssueTime().toInstant();
        if (iat != null && iat.isAfter(clock.instant().plus(allowedClockSkew))) {
            throw new SdJwtVerificationException("Key Binding JWT iat is too far in the future: " + iat);
        }
        if (iat != null && iat.isBefore(clock.instant().minus(allowedClockSkew))) {
            throw new SdJwtVerificationException("Key Binding JWT iat is too far in the past: " + iat);
        }
    }

    private static String getStringClaim(JWTClaimsSet claims, String name) {
        try {
            return claims.getStringClaim(name);
        } catch (ParseException e) {
            throw new SdJwtVerificationException("Key Binding JWT claim \"" + name + "\" is not a string", e);
        }
    }
}
