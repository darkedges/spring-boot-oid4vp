package com.darkedges.oid4vp.core.dcql.eval;

import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQueryReader;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Exercises {@link DcqlEvaluator} against the query_lang/*.json examples from OpenID4VP 1.1.
 *
 * <p>The real fixture at {@code credentials/sd_jwt_vc_unsecured.json} only has
 * {@code vct, given_name, family_name, birthdate} — several query examples ask for claims that fixture
 * doesn't have at all ({@code address.street_address}, {@code postal_code}, {@code locality},
 * {@code region}), or ask under a different key ({@code date_of_birth} vs. the fixture's
 * {@code birthdate}). Each such case is tested twice: once against the real fixture (asserting the
 * honest {@code Rejected} outcome), and once against a synthetic credential augmented with the missing
 * claims (asserting the intended success path). This is called out explicitly rather than silently
 * matching a query that the real fixture cannot actually satisfy.
 */
class DcqlEvaluatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final DcqlEvaluator evaluator = new DcqlEvaluator();

    private static final String IDENTITY_VCT = "https://credentials.example.com/identity_credential";

    private static JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static DcqlQuery readQuery(String fileName) {
        return DcqlQueryReader.read(FixtureLoader.readExampleJson("query_lang/" + fileName));
    }

    // ---- simple.json --------------------------------------------------------------------------

    @Test
    void simpleJson_realFixture_isRejectedBecauseAddressIsMissing() {
        DcqlQuery query = readQuery("simple.json");
        JsonNode realCredential = FixtureLoader.readExampleJson("credentials/sd_jwt_vc_unsecured.json");
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, realCredential, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Rejected.class);
    }

    @Test
    void simpleJson_syntheticCredentialWithAddress_isSelected() {
        DcqlQuery query = readQuery("simple.json");
        JsonNode credential = json("""
                {
                  "vct": "%s",
                  "given_name": "John",
                  "family_name": "Doe",
                  "address": {"street_address": "42 Market Street"}
                }
                """.formatted(IDENTITY_VCT));
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, credential, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Selected.class);
        var selected = (DcqlEvaluationResult.Selected) result;
        assertThat(selected.presentations()).containsOnlyKeys("my_credential");
        assertThat(selected.presentations().get("my_credential")).hasSize(1);
        ClaimSelection selection = selected.presentations().get("my_credential").get(0).claimSelection();
        assertThat(selection).isInstanceOfSatisfying(ClaimSelection.Selected.class,
                s -> assertThat(s.chosenClaims()).hasSize(3));
    }

    // ---- value_matching_simple.json ------------------------------------------------------------

    @Test
    void valueMatchingSimpleJson_realFixture_isRejectedBecauseAddressAndPostalCodeAreMissing() {
        DcqlQuery query = readQuery("value_matching_simple.json");
        JsonNode realCredential = FixtureLoader.readExampleJson("credentials/sd_jwt_vc_unsecured.json");
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, realCredential, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Rejected.class);
    }

    @Test
    void valueMatchingSimpleJson_matchingValues_isSelected() {
        DcqlQuery query = readQuery("value_matching_simple.json");
        JsonNode credential = json("""
                {
                  "vct": "%s",
                  "given_name": "John",
                  "family_name": "Doe",
                  "address": {"street_address": "42 Market Street"},
                  "postal_code": "90210"
                }
                """.formatted(IDENTITY_VCT));
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, credential, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Selected.class);
    }

    @Test
    void valueMatchingSimpleJson_nonMatchingFamilyNameValue_isRejected() {
        DcqlQuery query = readQuery("value_matching_simple.json");
        JsonNode credential = json("""
                {
                  "vct": "%s",
                  "given_name": "John",
                  "family_name": "Smith",
                  "address": {"street_address": "42 Market Street"},
                  "postal_code": "90210"
                }
                """.formatted(IDENTITY_VCT));
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, credential, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Rejected.class);
    }

    // ---- claims_alternatives.json ---------------------------------------------------------------

    @Test
    void claimsAlternativesJson_realFixture_isRejectedNeitherOptionSatisfiable() {
        // Real fixture has family_name ("a") but neither locality/region/date_of_birth ("c","d","e")
        // nor postal_code/date_of_birth ("b","e") — and its "birthdate" key doesn't match the query's
        // "date_of_birth" path at all.
        DcqlQuery query = readQuery("claims_alternatives.json");
        JsonNode realCredential = FixtureLoader.readExampleJson("credentials/sd_jwt_vc_unsecured.json");
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, realCredential, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Rejected.class);
    }

    @Test
    void claimsAlternativesJson_satisfiesFirstOptionWhenBothWouldBeSatisfiable() {
        // Has claims for BOTH options ("a","b","c","d","e" all present) — first option ["a","c","d","e"]
        // is preferred per spec ordering and must be the one chosen.
        DcqlQuery query = readQuery("claims_alternatives.json");
        JsonNode credential = json("""
                {
                  "vct": "%s",
                  "family_name": "Doe",
                  "postal_code": "90210",
                  "locality": "Milliways",
                  "region": "Betelgeuse",
                  "date_of_birth": "1940-01-01"
                }
                """.formatted(IDENTITY_VCT));
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, credential, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        var selected = (DcqlEvaluationResult.Selected) result;
        ClaimSelection selection = selected.presentations().get("pid").get(0).claimSelection();
        assertThat(selection).isInstanceOfSatisfying(ClaimSelection.Selected.class, s ->
                assertThat(s.chosenClaims()).extracting(c -> c.id().orElseThrow())
                        .containsExactly("a", "c", "d", "e"));
    }

    @Test
    void claimsAlternativesJson_fallsBackToSecondOptionWhenOnlyItIsSatisfiable() {
        DcqlQuery query = readQuery("claims_alternatives.json");
        JsonNode credential = json("""
                {
                  "vct": "%s",
                  "family_name": "Doe",
                  "postal_code": "90210",
                  "date_of_birth": "1940-01-01"
                }
                """.formatted(IDENTITY_VCT));
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, credential, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        var selected = (DcqlEvaluationResult.Selected) result;
        ClaimSelection selection = selected.presentations().get("pid").get(0).claimSelection();
        assertThat(selection).isInstanceOfSatisfying(ClaimSelection.Selected.class, s ->
                assertThat(s.chosenClaims()).extracting(c -> c.id().orElseThrow())
                        .containsExactly("a", "b", "e"));
    }

    @Test
    void claimsAlternativesJson_rejectedWhenNeitherOptionSatisfiable() {
        DcqlQuery query = readQuery("claims_alternatives.json");
        JsonNode credential = json("""
                {"vct": "%s", "family_name": "Doe"}
                """.formatted(IDENTITY_VCT));
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, credential, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Rejected.class);
    }

    // ---- credentials_alternatives.json (fully synthetic; vct's don't exist in docs/ fixtures) -----

    private static final String PID_VCT = "https://credentials.example.com/identity_credential";
    private static final String OTHER_PID_VCT = "https://othercredentials.example/pid";
    private static final String REDUCED_1_VCT = "https://credentials.example.com/reduced_identity_credential";
    private static final String REDUCED_2_VCT = "https://cred.example/residence_credential";
    private static final String NICE_TO_HAVE_VCT = "https://company.example/company_rewards";

    private static TestHeldCredential pidCredential() {
        return new TestHeldCredential(PID_VCT, json("""
                {"given_name": "John", "family_name": "Doe", "address": {"street_address": "42 Market Street"}}
                """), true);
    }

    private static TestHeldCredential otherPidCredential() {
        return new TestHeldCredential(OTHER_PID_VCT, json("""
                {"given_name": "John", "family_name": "Doe", "address": {"street_address": "42 Market Street"}}
                """), true);
    }

    private static TestHeldCredential reducedCred1() {
        return new TestHeldCredential(REDUCED_1_VCT, json("""
                {"family_name": "Doe", "given_name": "John"}
                """), true);
    }

    private static TestHeldCredential reducedCred2() {
        return new TestHeldCredential(REDUCED_2_VCT, json("""
                {"postal_code": "90210", "locality": "Milliways", "region": "Betelgeuse"}
                """), true);
    }

    private static TestHeldCredential niceToHaveCredential() {
        return new TestHeldCredential(NICE_TO_HAVE_VCT, json("""
                {"rewards_number": "12345"}
                """), true);
    }

    @Test
    void credentialsAlternatives_choosesFirstOptionWhenOnlyPidPresent() {
        DcqlQuery query = readQuery("credentials_alternatives.json");
        CredentialStore store = CredentialStore.of(List.of(pidCredential()));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        var selected = (DcqlEvaluationResult.Selected) result;
        assertThat(selected.presentations()).containsOnlyKeys("pid");
    }

    @Test
    void credentialsAlternatives_fallsBackToSecondOptionWhenOnlyOtherPidPresent() {
        DcqlQuery query = readQuery("credentials_alternatives.json");
        CredentialStore store = CredentialStore.of(List.of(otherPidCredential()));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        var selected = (DcqlEvaluationResult.Selected) result;
        assertThat(selected.presentations()).containsOnlyKeys("other_pid");
    }

    @Test
    void credentialsAlternatives_fallsBackToThirdOptionWhenBothReducedCredsPresent() {
        DcqlQuery query = readQuery("credentials_alternatives.json");
        CredentialStore store = CredentialStore.of(List.of(reducedCred1(), reducedCred2()));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        var selected = (DcqlEvaluationResult.Selected) result;
        assertThat(selected.presentations()).containsOnlyKeys("pid_reduced_cred_1", "pid_reduced_cred_2");
    }

    @Test
    void credentialsAlternatives_rejectedWhenNoOptionSatisfiable() {
        DcqlQuery query = readQuery("credentials_alternatives.json");
        CredentialStore store = CredentialStore.of(List.of(reducedCred1())); // only half of option 3

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Rejected.class);
    }

    @Test
    void credentialsAlternatives_includesOptionalNiceToHaveWhenPresent() {
        DcqlQuery query = readQuery("credentials_alternatives.json");
        CredentialStore store = CredentialStore.of(List.of(pidCredential(), niceToHaveCredential()));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        var selected = (DcqlEvaluationResult.Selected) result;
        assertThat(selected.presentations()).containsOnlyKeys("pid", "nice_to_have");
    }

    @Test
    void credentialsAlternatives_omitsOptionalNiceToHaveWithoutRejectingWhenAbsent() {
        DcqlQuery query = readQuery("credentials_alternatives.json");
        CredentialStore store = CredentialStore.of(List.of(pidCredential()));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        var selected = (DcqlEvaluationResult.Selected) result;
        assertThat(selected.presentations()).doesNotContainKey("nice_to_have");
    }

    // ---- multi_credentials.json (pid + mdl; mdl is mso_mdoc, unsupported in this phase) -----------

    @Test
    void multiCredentials_isRejectedBecauseMdlHasNoMatcherInThisPhase() {
        DcqlQuery query = readQuery("multi_credentials.json");
        // A pid credential that WOULD satisfy the "pid" half, to isolate that rejection is caused
        // specifically by "mdl" (mso_mdoc) having zero candidates, not by "pid" also failing.
        JsonNode pidWithAddress = json("""
                {
                  "vct": "%s",
                  "given_name": "John",
                  "family_name": "Doe",
                  "address": {"street_address": "42 Market Street"}
                }
                """.formatted(IDENTITY_VCT));
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, pidWithAddress, true)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Rejected.class);
    }

    @Test
    void multiCredentials_pidAloneSucceedsWhenMdlRequirementIsRemoved() {
        // Synthetic variant of the fixture with the mdl (mso_mdoc) entry removed, since this phase only
        // supports dc+sd-jwt; demonstrates the "pid" half alone is satisfiable.
        DcqlQuery fullQuery = readQuery("multi_credentials.json");
        DcqlQuery pidOnlyQuery = DcqlQuery.of(List.of(fullQuery.findCredential("pid").orElseThrow()));

        JsonNode pidWithAddress = json("""
                {
                  "vct": "%s",
                  "given_name": "John",
                  "family_name": "Doe",
                  "address": {"street_address": "42 Market Street"}
                }
                """.formatted(IDENTITY_VCT));
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, pidWithAddress, true)));

        DcqlEvaluationResult result = evaluator.evaluate(pidOnlyQuery, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Selected.class);
        var selected = (DcqlEvaluationResult.Selected) result;
        assertThat(selected.presentations()).containsOnlyKeys("pid");
    }

    // ---- require_cryptographic_holder_binding -------------------------------------------------

    @Test
    void credentialWithoutHolderBindingIsExcludedWhenRequired() {
        DcqlQuery query = readQuery("simple.json"); // require_cryptographic_holder_binding defaults to true
        JsonNode credential = json("""
                {
                  "vct": "%s",
                  "given_name": "John",
                  "family_name": "Doe",
                  "address": {"street_address": "42 Market Street"}
                }
                """.formatted(IDENTITY_VCT));
        CredentialStore store = CredentialStore.of(List.of(new TestHeldCredential(IDENTITY_VCT, credential, false)));

        DcqlEvaluationResult result = evaluator.evaluate(query, store);

        assertThat(result).isInstanceOf(DcqlEvaluationResult.Rejected.class);
    }
}
