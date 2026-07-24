package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.verifier.encryption.ResponseDecryptor;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link ResponseEncryptor} — the Wallet-side counterpart to {@code oid4vp-verifier-core}'s
 * {@code ResponseDecryptor}, had no test at all before (only exercised manually, via the demo Wallet).
 * Round-trips through the real {@code ResponseDecryptor} to prove the two sides actually agree on the JWE
 * shape, rather than just asserting {@link ResponseEncryptor#encrypt} doesn't throw.
 */
class ResponseEncryptorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ECKey generateEncryptionKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID("verifier-enc-1").generate();
    }

    private static ObjectNode asJwkSet(JsonNode... jwks) {
        ArrayNode keys = JsonNodeFactory.instance.arrayNode();
        for (JsonNode jwk : jwks) {
            keys.add(jwk);
        }
        return JsonNodeFactory.instance.objectNode().set("keys", keys);
    }

    private static String decodedHeader(String jwe) {
        return new String(Base64.getUrlDecoder().decode(jwe.split("\\.")[0]));
    }

    @Test
    void roundTripsThroughTheRealResponseDecryptor() throws Exception {
        ECKey verifierKey = generateEncryptionKey();
        JsonNode publicJwk = MAPPER.readTree(verifierKey.toPublicJWK().toJSONString());
        JsonNode publicJwks = asJwkSet(publicJwk);
        JsonNode privateJwks = asJwkSet(MAPPER.readTree(verifierKey.toJSONString()));

        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("vp_token", "eyJhbGciOiJFUzI1NiJ9...");
        payload.put("state", "the-state-value");

        String jwe = ResponseEncryptor.encrypt(payload, publicJwks, List.of("A128GCM"));

        JsonNode decrypted = ResponseDecryptor.decrypt(jwe, privateJwks);
        assertThat(decrypted).isEqualTo(payload);
    }

    @Test
    void theResponseDecryptorResolvesTheSamePublicKeyThatWasUsedToEncrypt() throws Exception {
        ECKey verifierKey = generateEncryptionKey();
        JsonNode publicJwk = MAPPER.readTree(verifierKey.toPublicJWK().toJSONString());
        JsonNode publicJwks = asJwkSet(publicJwk);
        JsonNode privateJwks = asJwkSet(MAPPER.readTree(verifierKey.toJSONString()));

        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("vp_token", "x");

        String jwe = ResponseEncryptor.encrypt(payload, publicJwks, List.of("A128GCM"));

        Optional<JsonNode> resolved = ResponseDecryptor.resolveResponseEncryptionPublicJwk(jwe, privateJwks);
        assertThat(resolved).isPresent();
        assertThat(resolved.get().get("x").asText()).isEqualTo(publicJwk.get("x").asText());
        assertThat(resolved.get().get("y").asText()).isEqualTo(publicJwk.get("y").asText());
    }

    @Test
    void defaultsToA128GcmWhenNoEncValuesAreSupplied() throws Exception {
        ECKey verifierKey = generateEncryptionKey();
        JsonNode publicJwks = asJwkSet(MAPPER.readTree(verifierKey.toPublicJWK().toJSONString()));

        String jwe = ResponseEncryptor.encrypt(MAPPER.createObjectNode(), publicJwks, List.of());

        assertThat(decodedHeader(jwe)).contains("\"enc\":\"A128GCM\"");
    }

    @Test
    void picksTheFirstSupportedEncValueWhenSeveralAreOffered() throws Exception {
        ECKey verifierKey = generateEncryptionKey();
        JsonNode publicJwks = asJwkSet(MAPPER.readTree(verifierKey.toPublicJWK().toJSONString()));

        String jwe = ResponseEncryptor.encrypt(MAPPER.createObjectNode(), publicJwks, List.of("A256GCM", "A128GCM"));

        assertThat(decodedHeader(jwe)).contains("\"enc\":\"A256GCM\"");
    }

    @Test
    void rejectsAJwksWithNoKeys() {
        JsonNode emptyJwks = asJwkSet();
        assertThatThrownBy(() -> ResponseEncryptor.encrypt(MAPPER.createObjectNode(), emptyJwks, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsAJwksWithMoreThanOneKey() throws Exception {
        JsonNode key1 = MAPPER.readTree(generateEncryptionKey().toPublicJWK().toJSONString());
        JsonNode key2 = MAPPER.readTree(generateEncryptionKey().toPublicJWK().toJSONString());
        JsonNode twoKeys = asJwkSet(key1, key2);

        assertThatThrownBy(() -> ResponseEncryptor.encrypt(MAPPER.createObjectNode(), twoKeys, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
