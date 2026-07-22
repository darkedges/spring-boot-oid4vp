package com.darkedges.oid4vp.core.dcql;

import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Round-trips every DCQL query example under {@code docs/1.1/examples/query_lang/} through
 * {@link DcqlQueryReader}/{@link DcqlQueryWriter} and asserts the re-serialized JSON is structurally
 * identical to the original fixture. {@code simple_mdoc.json} and {@code complex_mdoc.json} are
 * {@code mso_mdoc}-only and parse into stub {@link MsoMdocMeta} objects — this test only checks
 * shape/parse correctness for those, never evaluates them (mdoc matching is out of scope in this phase).
 */
class DcqlQueryJsonMappingTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "simple.json",
            "simple_mdoc.json",
            "value_matching_simple.json",
            "claims_alternatives.json",
            "credentials_alternatives.json",
            "multi_credentials.json",
            "complex_mdoc.json"
    })
    void roundTripsExactly(String fileName) {
        JsonNode original = FixtureLoader.readExampleJson("query_lang/" + fileName);

        DcqlQuery parsed = DcqlQueryReader.read(original);
        JsonNode reSerialized = DcqlQueryWriter.write(parsed);

        assertThat(reSerialized).as("round-trip of %s", fileName).isEqualTo(original);
    }
}
