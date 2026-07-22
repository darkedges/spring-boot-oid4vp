package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Parses the three disclosures given inline in OpenID4VP 1.1, "IETF SD-JWT VC" > "Example Credential"
 * (transcribed to {@code sd_jwt_vc_disclosures.json}, since they're spec prose, not a docs/ fixture
 * file) and confirms both the decoded contents and the recomputed SHA-256 digest match exactly.
 */
class DisclosureTest {

    @Test
    void decodesAndDigestsEachDocumentedDisclosure() {
        JsonNode fixture = FixtureLoader.readJson("sd_jwt_vc_disclosures.json");

        for (JsonNode entry : fixture.get("disclosures")) {
            Disclosure disclosure = Disclosure.parse(entry.get("disclosureBase64Url").asText());

            assertThat(disclosure.salt()).as(entry.get("claimName").asText() + " salt")
                    .isEqualTo(entry.get("salt").asText());
            assertThat(disclosure.claimName()).contains(entry.get("claimName").asText());
            assertThat(disclosure.claimValue().asText()).isEqualTo(entry.get("value").asText());
            assertThat(disclosure.digest()).as(entry.get("claimName").asText() + " digest")
                    .isEqualTo(entry.get("sha256HashBase64Url").asText());
        }
    }

    @Test
    void createObjectPropertyRoundTripsThroughParse() {
        Disclosure created = Disclosure.createObjectProperty(
                "2GLC42sKQveCfGfryNRN9w",
                "given_name",
                com.fasterxml.jackson.databind.node.TextNode.valueOf("John"));

        Disclosure reparsed = Disclosure.parse(created.rawBase64Url());

        assertThat(reparsed.salt()).isEqualTo("2GLC42sKQveCfGfryNRN9w");
        assertThat(reparsed.claimName()).contains("given_name");
        assertThat(reparsed.claimValue().asText()).isEqualTo("John");
        assertThat(reparsed.digest()).isEqualTo(created.digest());
    }
}
