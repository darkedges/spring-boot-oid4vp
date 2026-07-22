package com.darkedges.oid4vp.core.dcql;

import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Exercises the exact "Claims Path Pointer Example" from OpenID4VP 1.1, ("Claims Path Pointer" >
 * "Claims Path Pointer Example"), transcribed to
 * {@code oid4vp-test-fixtures/src/main/resources-spec-transcribed/claims_path_pointer_example.json}.
 */
class ClaimsPathPointerTest {

    private final JsonNode arthurDent = FixtureLoader.readJson("claims_path_pointer_example.json");

    @Test
    void selectsTopLevelStringClaim() {
        List<JsonNode> selected = ClaimsPathPointer.of("name").select(arthurDent);

        assertThat(selected).hasSize(1);
        assertThat(selected.get(0).asText()).isEqualTo("Arthur Dent");
    }

    @Test
    void selectsWholeObjectClaim() {
        List<JsonNode> selected = ClaimsPathPointer.of("address").select(arthurDent);

        assertThat(selected).hasSize(1);
        assertThat(selected.get(0).get("locality").asText()).isEqualTo("Milliways");
    }

    @Test
    void selectsNestedStringClaim() {
        List<JsonNode> selected = ClaimsPathPointer.of("address", "street_address").select(arthurDent);

        assertThat(selected).hasSize(1);
        assertThat(selected.get(0).asText()).isEqualTo("42 Market Street");
    }

    @Test
    void selectsAllArrayElementsThenAKey() {
        List<JsonNode> selected = ClaimsPathPointer.of("degrees", null, "type").select(arthurDent);

        assertThat(selected).extracting(JsonNode::asText)
                .containsExactly("Bachelor of Science", "Master of Science");
    }

    @Test
    void selectsArrayElementByIndex() {
        List<JsonNode> selected = ClaimsPathPointer.of("nationalities", 1).select(arthurDent);

        assertThat(selected).hasSize(1);
        assertThat(selected.get(0).asText()).isEqualTo("Betelgeusian");
    }

    @Test
    void abortsWhenKeyComponentAppliedToNonObject() {
        // "name" selects a string; then addressing a key within it is a type mismatch, not a missing key.
        assertThatThrownBy(() -> ClaimsPathPointer.of("name", "nested").select(arthurDent))
                .isInstanceOf(ClaimsPathPointerException.class);
    }

    @Test
    void abortsWhenAllElementsComponentAppliedToNonArray() {
        assertThatThrownBy(() -> ClaimsPathPointer.of("address", null).select(arthurDent))
                .isInstanceOf(ClaimsPathPointerException.class);
    }

    @Test
    void abortsWhenIndexComponentAppliedToNonArray() {
        assertThatThrownBy(() -> ClaimsPathPointer.of("address", 0).select(arthurDent))
                .isInstanceOf(ClaimsPathPointerException.class);
    }

    @Test
    void missingKeyRemovesElementFromSelectionRatherThanAborting() {
        // "degrees", null selects both degree objects; "does_not_exist" removes both (neither has that
        // key) leaving an empty selection, which THEN aborts per step 3 (empty final selection).
        assertThatThrownBy(() -> ClaimsPathPointer.of("degrees", null, "does_not_exist").select(arthurDent))
                .isInstanceOf(ClaimsPathPointerException.class);
    }

    @Test
    void outOfRangeIndexAbortsBecauseFinalSelectionIsEmpty() {
        assertThatThrownBy(() -> ClaimsPathPointer.of("nationalities", 5).select(arthurDent))
                .isInstanceOf(ClaimsPathPointerException.class);
    }
}
