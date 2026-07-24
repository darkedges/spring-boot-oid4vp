package com.darkedges.oid4vp.verifier.encryption;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import java.util.UUID;

/**
 * Generates a fresh EC (P-256) response-encryption keypair, unique per call — required by HAIP
 * ("Verifiers MUST supply an ephemeral encryption public key specific to each Authorization Request"),
 * not just a demo nicety: a Wallet that ever sees the same response-encryption public key across two
 * different Authorization Requests fails conformance for reusing it.
 */
public final class EphemeralEncryptionKeyGenerator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private EphemeralEncryptionKeyGenerator() {}

    public static EphemeralEncryptionKeyPair generate() {
        ECKey key;
        try {
            key = new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .keyUse(KeyUse.ENCRYPTION)
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to generate an ephemeral response-encryption key", e);
        }
        try {
            JsonNode publicJwk = MAPPER.readTree(key.toPublicJWK().toJSONString());
            JsonNode privateJwk = MAPPER.readTree(key.toJSONString());
            return new EphemeralEncryptionKeyPair(publicJwk, privateJwk);
        } catch (Exception e) {
            throw new IllegalStateException("failed to serialize the generated ephemeral key", e);
        }
    }
}
