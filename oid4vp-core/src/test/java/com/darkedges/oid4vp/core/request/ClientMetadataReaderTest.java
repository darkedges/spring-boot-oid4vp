package com.darkedges.oid4vp.core.request;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ClientMetadataReaderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void roundTripsThroughClientMetadataWriter() throws Exception {
        JsonNode jwks = MAPPER.readTree("""
                {"keys":[{"kty":"EC","crv":"P-256","use":"enc","kid":"enc-1","x":"abc","y":"def","alg":"ECDH-ES"}]}""");
        ClientMetadata original = new ClientMetadata(
                Optional.of(jwks),
                List.of("A128GCM", "A256GCM"),
                Map.of(CredentialFormat.DC_SD_JWT, MAPPER.readTree("{\"sd-jwt_alg_values\":[\"ES256\"]}")));

        ObjectNode written = ClientMetadataWriter.write(original);
        ClientMetadata read = ClientMetadataReader.read(written);

        assertThat(read.jwks()).contains(jwks);
        assertThat(read.encryptedResponseEncValuesSupported()).containsExactly("A128GCM", "A256GCM");
        assertThat(read.vpFormatsSupported()).containsKey(CredentialFormat.DC_SD_JWT);
    }

    @Test
    void absentFieldsProduceEmptyDefaults() {
        ClientMetadata read = ClientMetadataReader.read(MAPPER.createObjectNode());

        assertThat(read.jwks()).isEmpty();
        assertThat(read.encryptedResponseEncValuesSupported()).isEmpty();
        assertThat(read.vpFormatsSupported()).isEmpty();
    }
}
