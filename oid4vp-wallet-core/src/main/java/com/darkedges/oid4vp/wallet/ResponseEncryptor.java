package com.darkedges.oid4vp.wallet;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;

import java.text.ParseException;
import java.util.List;

/**
 * Builds an encrypted Authorization Response ({@code direct_post.jwt} / {@code dc_api.jwt}): an unsigned
 * JWE whose payload is a JSON object of Authorization Response parameters as top-level members, encrypted
 * to the Verifier's response-encryption public key (its {@code client_metadata.jwks}) — the Wallet-side
 * counterpart to {@code oid4vp-verifier-core}'s {@code ResponseDecryptor}.
 */
public final class ResponseEncryptor {

    private ResponseEncryptor() {}

    /**
     * @param payload                the Authorization Response parameters (e.g. {@code vp_token}, {@code state})
     *                               as a single JSON object, to become the JWE's plaintext.
     * @param publicJwksJson         the Verifier's {@code client_metadata.jwks} (a JWK Set) — exactly one key
     *                               is expected, per HAIP's "fresh ephemeral key per request" convention.
     * @param encValuesSupported     the Verifier's {@code encrypted_response_enc_values_supported}, in
     *                               preference order; defaults to {@code ["A128GCM"]} when empty, per spec.
     */
    public static String encrypt(JsonNode payload, JsonNode publicJwksJson, List<String> encValuesSupported) {
        JWKSet jwkSet;
        try {
            jwkSet = JWKSet.parse(publicJwksJson.toString());
        } catch (ParseException e) {
            throw new IllegalArgumentException("Verifier's client_metadata.jwks is not a valid JWK Set", e);
        }
        List<JWK> keys = jwkSet.getKeys();
        if (keys.size() != 1) {
            throw new IllegalArgumentException(
                    "expected exactly one response-encryption key in client_metadata.jwks, found " + keys.size());
        }
        JWK key = keys.get(0);

        EncryptionMethod enc = selectEncryptionMethod(encValuesSupported);
        JWEHeader.Builder headerBuilder = new JWEHeader.Builder(selectAlgorithm(key), enc);
        if (key.getKeyID() != null) {
            headerBuilder.keyID(key.getKeyID());
        }

        JWEObject jwe = new JWEObject(headerBuilder.build(), new Payload(payload.toString()));
        try {
            jwe.encrypt(createEncrypter(key));
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to encrypt Authorization Response", e);
        }
        return jwe.serialize();
    }

    private static EncryptionMethod selectEncryptionMethod(List<String> encValuesSupported) {
        List<String> candidates = encValuesSupported.isEmpty() ? List.of("A128GCM") : encValuesSupported;
        return EncryptionMethod.parse(candidates.get(0));
    }

    private static JWEAlgorithm selectAlgorithm(JWK key) {
        return switch (key) {
            case ECKey ignored -> JWEAlgorithm.ECDH_ES;
            case RSAKey ignored -> JWEAlgorithm.RSA_OAEP_256;
            case OctetKeyPair ignored -> JWEAlgorithm.ECDH_ES;
            default -> throw new IllegalArgumentException("unsupported JWK type for response encryption: " + key.getKeyType());
        };
    }

    private static JWEEncrypter createEncrypter(JWK key) {
        try {
            return switch (key) {
                case ECKey ecKey -> new ECDHEncrypter(ecKey);
                case RSAKey rsaKey -> new RSAEncrypter(rsaKey);
                case OctetKeyPair okpKey -> new X25519Encrypter(okpKey);
                default -> throw new IllegalArgumentException(
                        "unsupported JWK type for response encryption: " + key.getKeyType());
            };
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to construct encrypter for the response encryption key", e);
        }
    }
}
