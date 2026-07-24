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

import java.nio.charset.StandardCharsets;
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
     * The Wallet-generated nonce mdoc's {@code OID4VPHandover} requires (ISO 18013-7 Annex B / OpenID4VP's
     * mdoc appendix) — carried in the encrypted response JWE's {@code apu} header (RFC 7518 §4.6.1.2,
     * base64url), the only channel it has back to the Verifier since it has to be known before the
     * response is even decrypted. Reads the header only — no key/decryption needed. Empty for a
     * non-encrypted response, or one with no {@code apu} (i.e. every non-mdoc presentation).
     */
    public static Optional<String> extractMdocGeneratedNonce(String jwe) {
        JWEObject jweObject;
        try {
            jweObject = JWEObject.parse(jwe);
        } catch (ParseException e) {
            throw new Oid4vpException(Oid4vpErrorCode.INVALID_REQUEST, "\"response\" is not a valid JWE", e);
        }
        var apu = jweObject.getHeader().getAgreementPartyUInfo();
        return apu == null ? Optional.empty() : Optional.of(new String(apu.decode(), StandardCharsets.UTF_8));
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
