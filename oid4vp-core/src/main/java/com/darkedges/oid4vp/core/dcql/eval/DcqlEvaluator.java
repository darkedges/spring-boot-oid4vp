package com.darkedges.oid4vp.core.dcql.eval;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointerException;
import com.darkedges.oid4vp.core.dcql.ClaimsQuery;
import com.darkedges.oid4vp.core.dcql.ClaimsQueryValue;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.CredentialSetQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.TrustedAuthoritiesQuery;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Evaluates a {@link DcqlQuery} against a {@link CredentialStore}, implementing the OpenID4VP 1.1
 * "Selecting Claims" and "Selecting Credentials" processing rules.
 *
 * <p>Design notes:
 * <ul>
 *   <li>Claim selection ({@link #selectClaims}) follows the spec literally: absent {@code claims} ⇒
 *       mandatory-only; {@code claims} without {@code claim_sets} ⇒ all-or-nothing; both present ⇒ the
 *       first satisfiable {@code claim_sets} option wins (the Wallet SHOULD prefer it), any other
 *       outcome for that credential is "does not satisfy this query".</li>
 *   <li>Credential selection ({@link #evaluate}) enforces that an unsatisfiable required constraint
 *       (a bare {@code credentials} entry with no {@code credential_sets}, or a required
 *       {@link CredentialSetQuery}) rejects the whole query — never a partial {@link DcqlEvaluationResult.Selected}.</li>
 *   <li>When {@code credential_sets} is present, the <em>first</em> satisfiable {@code options} entry
 *       per set is chosen. The spec doesn't mandate this ordering the way it does for {@code claim_sets}
 *       preference, so this is a documented implementation choice, not a normative requirement.</li>
 *   <li>Unsupported Credential Formats (no {@link CredentialStore} entries of that format exist, since
 *       only {@code dc+sd-jwt} is implemented in this phase) naturally yield zero candidates, which
 *       correctly forces rejection of any query that requires them.</li>
 * </ul>
 */
public final class DcqlEvaluator {

    public DcqlEvaluationResult evaluate(DcqlQuery query, CredentialStore store) {
        Map<String, List<CredentialPresentationPlan>> candidatesByQueryId = new LinkedHashMap<>();
        for (CredentialQuery credentialQuery : query.credentials()) {
            candidatesByQueryId.put(credentialQuery.id(), findCandidates(credentialQuery, store));
        }

        if (query.credentialSets().isEmpty()) {
            return selectWithoutCredentialSets(query, candidatesByQueryId);
        }
        return selectWithCredentialSets(query.credentialSets().get(), candidatesByQueryId);
    }

    private static DcqlEvaluationResult selectWithoutCredentialSets(
            DcqlQuery query, Map<String, List<CredentialPresentationPlan>> candidatesByQueryId) {
        Map<String, List<CredentialPresentationPlan>> result = new LinkedHashMap<>();
        for (CredentialQuery credentialQuery : query.credentials()) {
            List<CredentialPresentationPlan> candidates = candidatesByQueryId.get(credentialQuery.id());
            if (candidates.isEmpty()) {
                return new DcqlEvaluationResult.Rejected(
                        "required credential query \"" + credentialQuery.id() + "\" has no matching credentials");
            }
            result.put(credentialQuery.id(), candidates);
        }
        return new DcqlEvaluationResult.Selected(result);
    }

    private static DcqlEvaluationResult selectWithCredentialSets(
            List<CredentialSetQuery> credentialSets, Map<String, List<CredentialPresentationPlan>> candidatesByQueryId) {
        Map<String, List<CredentialPresentationPlan>> result = new LinkedHashMap<>();
        for (CredentialSetQuery set : credentialSets) {
            Optional<List<String>> satisfiedOption = set.options().stream()
                    .filter(option -> option.stream()
                            .allMatch(id -> !candidatesByQueryId.getOrDefault(id, List.of()).isEmpty()))
                    .findFirst();

            if (satisfiedOption.isPresent()) {
                for (String id : satisfiedOption.get()) {
                    result.put(id, candidatesByQueryId.get(id));
                }
            } else if (set.required()) {
                return new DcqlEvaluationResult.Rejected(
                        "required credential_sets entry not satisfiable: options=" + set.options());
            }
        }
        return new DcqlEvaluationResult.Selected(result);
    }

    private static List<CredentialPresentationPlan> findCandidates(CredentialQuery query, CredentialStore store) {
        List<CredentialPresentationPlan> candidates = new ArrayList<>();
        for (HeldCredential credential : store.findByFormat(query.format())) {
            if (!credential.matchesMeta(query.meta())) {
                continue;
            }
            if (!matchesTrustedAuthorities(credential, query.trustedAuthorities())) {
                continue;
            }
            if (query.requireCryptographicHolderBinding() && !credential.hasCryptographicHolderBinding()) {
                continue;
            }
            selectClaims(query, credential).ifPresent(selection -> candidates.add(
                    new CredentialPresentationPlan(credential, selection)));
        }
        return candidates;
    }

    private static boolean matchesTrustedAuthorities(HeldCredential credential, List<TrustedAuthoritiesQuery> queries) {
        if (queries.isEmpty()) {
            return true;
        }
        return queries.stream().anyMatch(credential::matchesTrustedAuthority);
    }

    private static Optional<ClaimSelection> selectClaims(CredentialQuery query, HeldCredential credential) {
        if (query.claims().isEmpty()) {
            return Optional.of(ClaimSelection.MandatoryOnly.INSTANCE);
        }
        List<ClaimsQuery> claims = query.claims().get();

        if (query.claimSets().isEmpty()) {
            if (claims.stream().allMatch(claim -> canSatisfy(credential, claim))) {
                return Optional.of(new ClaimSelection.Selected(claims));
            }
            return Optional.empty();
        }

        Map<String, ClaimsQuery> claimsById = new LinkedHashMap<>();
        for (ClaimsQuery claim : claims) {
            claim.id().ifPresent(id -> claimsById.put(id, claim));
        }
        for (List<String> option : query.claimSets().get()) {
            List<ClaimsQuery> chosen = option.stream().map(claimsById::get).toList();
            if (chosen.stream().allMatch(claim -> canSatisfy(credential, claim))) {
                return Optional.of(new ClaimSelection.Selected(chosen));
            }
        }
        return Optional.empty();
    }

    private static boolean canSatisfy(HeldCredential credential, ClaimsQuery claim) {
        List<JsonNode> selected;
        try {
            selected = claim.path().select(credential.claimsView());
        } catch (ClaimsPathPointerException notPresent) {
            return false;
        }

        Optional<List<ClaimsQueryValue>> values = claim.values();
        if (values.isEmpty()) {
            return true;
        }
        return selected.stream().anyMatch(node -> values.get().stream().anyMatch(v -> v.matches(node)));
    }
}
