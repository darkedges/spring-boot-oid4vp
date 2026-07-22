package com.darkedges.oid4vp.verifier.encryption;

import com.darkedges.oid4vp.core.response.Oid4vpException;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Decrypts the exact worked example from OpenID4VP 1.1, "Encrypted Responses" (an ECDH-ES/A128GCM JWE
 * over a {@code dc+sd-jwt} response), transcribed to {@code encrypted_response_example.json}.
 */
class ResponseDecryptorTest {

    private final JsonNode fixture = FixtureLoader.readJson("encrypted_response_example.json");

    private static ObjectNode asJwkSet(JsonNode jwk) {
        ArrayNode keys = JsonNodeFactory.instance.arrayNode().add(jwk);
        return JsonNodeFactory.instance.objectNode().set("keys", keys);
    }

    @Test
    void decryptsTheSpecExampleResponseExactly() {
        JsonNode decrypted = ResponseDecryptor.decrypt(fixture.get("responseJwe").asText(), asJwkSet(fixture.get("decryptionJwk")));

        assertThat(decrypted).isEqualTo(fixture.get("expectedPayload"));
    }

    @Test
    void selectsTheMatchingKeyByKidAmongMultipleConfiguredKeys() {
        ObjectNode decoy = fixture.get("decryptionJwk").deepCopy();
        decoy.put("kid", "some-other-key");
        ArrayNode keys = JsonNodeFactory.instance.arrayNode().add(decoy).add(fixture.get("decryptionJwk"));
        ObjectNode jwks = JsonNodeFactory.instance.objectNode().set("keys", keys);

        JsonNode decrypted = ResponseDecryptor.decrypt(fixture.get("responseJwe").asText(), jwks);

        assertThat(decrypted).isEqualTo(fixture.get("expectedPayload"));
    }

    @Test
    void rejectsAnUnknownKid() {
        ObjectNode wrongKid = fixture.get("decryptionJwk").deepCopy();
        wrongKid.put("kid", "not-the-right-kid");
        ArrayNode keys = JsonNodeFactory.instance.arrayNode().add(wrongKid);
        ObjectNode jwks = JsonNodeFactory.instance.objectNode().set("keys", keys);

        assertThatThrownBy(() -> ResponseDecryptor.decrypt(fixture.get("responseJwe").asText(), jwks))
                .isInstanceOf(Oid4vpException.class);
    }

    @Test
    void rejectsAMalformedJwe() {
        ArrayNode keys = JsonNodeFactory.instance.arrayNode().add(fixture.get("decryptionJwk"));
        ObjectNode jwks = JsonNodeFactory.instance.objectNode().set("keys", keys);

        assertThatThrownBy(() -> ResponseDecryptor.decrypt("not-a-jwe", jwks)).isInstanceOf(Oid4vpException.class);
    }
}
