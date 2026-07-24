package com.darkedges.oid4vp.verifier.encryption;

import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import com.darkedges.oid4vp.core.response.Oid4vpException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

/**
 * Decrypts an encrypted Authorization Response (the {@code response} JWT of {@code direct_post.jwt} /
 * {@code dc_api.jwt}) per OpenID4VP 1.1 "Encrypted Responses": an unsigned JWE whose payload is a JSON
 * object of Authorization Response parameters as top-level members.
 *
 * <p>Key selection follows the spec's rule: match by JWE {@code kid} header if present, else require
 * there to be exactly one candidate key. JOSE HPKE integrated encryption mode (a separate, non-JWE
 * encryption mechanism) is not implemented — only standard JWE (RFC 7516/7518) algorithms are supported.
 */
public final class ResponseDecryptor {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ResponseDecryptor() {}

    public static JsonNode decrypt(String jwe, JsonNode privateJwksJson) {
        JWEObject jweObject;
        try {
            jweObject = JWEObject.parse(jwe);
        } catch (ParseException e) {
            throw new Oid4vpException(Oid4vpErrorCode.INVALID_REQUEST, "\"response\" is not a valid JWE", e);
        }

        JWKSet jwkSet;
        try {
            jwkSet = JWKSet.parse(privateJwksJson.toString());
        } catch (ParseException e) {
            throw new IllegalStateException("configured response decryption JWK Set is not valid JSON", e);
        }

        JWK key = selectKey(jwkSet, jweObject.getHeader().getKeyID());

        try {
            jweObject.decrypt(createDecrypter(key));
        } catch (JOSEException e) {
            throw new Oid4vpException(Oid4vpErrorCode.INVALID_REQUEST, "failed to decrypt Authorization Response", e);
        }

        try {
            return MAPPER.readTree(jweObject.getPayload().toString());
        } catch (Exception e) {
            throw new Oid4vpException(Oid4vpErrorCode.INVALID_REQUEST, "decrypted Authorization Response payload is not valid JSON", e);
        }
    }

    /**
     * The public half of the response-encryption key this JWE was actually encrypted to — mdoc's
     * {@code OpenID4VPHandover} hashes its RFC 7638 thumbprint (OpenID4VP 1.1 §"Handover and
     * SessionTranscript Definitions"), computed independently by both sides from a key they each already
     * hold, rather than a value either side has to invent and communicate. Resolves the same key
     * {@link #decrypt} would select (by JWE {@code kid} header, falling back to the sole candidate key),
     * but only needs the private JWK Set to look it up — no decryption performed here.
     */
    public static Optional<JsonNode> resolveResponseEncryptionPublicJwk(String jwe, JsonNode privateJwksJson) {
        JWEObject jweObject;
        try {
            jweObject = JWEObject.parse(jwe);
        } catch (ParseException e) {
            throw new Oid4vpException(Oid4vpErrorCode.INVALID_REQUEST, "\"response\" is not a valid JWE", e);
        }
        JWKSet jwkSet;
        try {
            jwkSet = JWKSet.parse(privateJwksJson.toString());
        } catch (ParseException e) {
            throw new IllegalStateException("configured response decryption JWK Set is not valid JSON", e);
        }
        JWK key = selectKey(jwkSet, jweObject.getHeader().getKeyID());
        try {
            return Optional.of(MAPPER.readTree(key.toPublicJWK().toJSONString()));
        } catch (Exception e) {
            throw new IllegalStateException("failed to serialize the response decryption key's public half", e);
        }
    }

    private static JWK selectKey(JWKSet jwkSet, String kid) {
        if (kid != null) {
            JWK key = jwkSet.getKeyByKeyId(kid);
            if (key == null) {
                throw new Oid4vpException(Oid4vpErrorCode.INVALID_REQUEST, "no response decryption key found for kid: " + kid);
            }
            return key;
        }
        List<JWK> keys = jwkSet.getKeys();
        if (keys.size() == 1) {
            return keys.get(0);
        }
        throw new Oid4vpException(Oid4vpErrorCode.INVALID_REQUEST,
                "encrypted response has no \"kid\" and more than one response decryption key is configured");
    }

    private static JWEDecrypter createDecrypter(JWK key) {
        try {
            return switch (key) {
                case ECKey ecKey -> new ECDHDecrypter(ecKey);
                case RSAKey rsaKey -> new RSADecrypter(rsaKey);
                case OctetKeyPair okpKey -> new X25519Decrypter(okpKey);
                default -> throw new IllegalArgumentException(
                        "unsupported JWK type for response decryption: " + key.getKeyType());
            };
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to construct decrypter for the response decryption key", e);
        }
    }
}
