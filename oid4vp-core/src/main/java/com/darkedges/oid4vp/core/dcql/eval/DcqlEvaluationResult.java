package com.darkedges.oid4vp.core.dcql.eval;

import java.util.List;
import java.util.Map;

/** The outcome of evaluating a DCQL query against a {@link CredentialStore}. */
public sealed interface DcqlEvaluationResult {

    /**
     * The query is satisfiable. {@code presentations} maps each satisfied Credential Query {@code id}
     * to the Credential(s)/claim-selection plan(s) that satisfy it. Per OpenID4VP 1.1, this is never a
     * partial result: every non-optional requirement (bare {@code credentials} entries when
     * {@code credential_sets} is absent, or every required {@link com.darkedges.oid4vp.core.dcql.CredentialSetQuery})
     * was satisfiable, or the whole result would instead be {@link Rejected}.
     */
    record Selected(Map<String, List<CredentialPresentationPlan>> presentations) implements DcqlEvaluationResult {
        public Selected {
            presentations = Map.copyOf(presentations);
        }
    }

    /** The query could not be satisfied; {@code reason} is a human-readable diagnostic, not a security
     * boundary (see privacy considerations around not distinguishing rejection causes to a Verifier). */
    record Rejected(String reason) implements DcqlEvaluationResult {}
}
