package com.darkedges.oid4vp.core.request;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class VerifierInfoReaderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void parsesEntriesWithAndWithoutCredentialIds() throws Exception {
        JsonNode array = MAPPER.readTree("""
                [
                  {"format":"jwt","data":"eyJhbGciOiJFUzI1NiJ9...","credential_ids":["employee"]},
                  {"format":"jwt","data":"eyJhbGciOiJFUzI1NiJ9..."}
                ]""");

        List<VerifierInfoEntry> entries = VerifierInfoReader.read(array);

        assertThat(entries).hasSize(2);
        assertThat(entries.get(0).format()).isEqualTo("jwt");
        assertThat(entries.get(0).credentialIds()).contains(List.of("employee"));
        assertThat(entries.get(1).credentialIds()).isEmpty();
    }

    @Test
    void missingOrNullArrayProducesEmptyList() {
        assertThat(VerifierInfoReader.read(null)).isEmpty();
        assertThat(VerifierInfoReader.read(MAPPER.nullNode())).isEmpty();
    }

    @Test
    void roundTripsThroughAuthorizationRequestWriter() throws Exception {
        VerifierInfoEntry entry = new VerifierInfoEntry(
                "jwt", MAPPER.readTree("\"eyJhbGciOiJFUzI1NiJ9...\""), Optional.of(List.of("employee")));

        com.fasterxml.jackson.databind.node.ArrayNode array = MAPPER.createArrayNode();
        com.fasterxml.jackson.databind.node.ObjectNode entryNode = MAPPER.createObjectNode();
        entryNode.put("format", entry.format());
        entryNode.set("data", entry.data());
        entryNode.putArray("credential_ids").add("employee");
        array.add(entryNode);

        List<VerifierInfoEntry> read = VerifierInfoReader.read(array);

        assertThat(read).containsExactly(entry);
    }
}
