package com.darkedges.oid4vp.core.dcql.eval;

import com.darkedges.oid4vp.core.dcql.ClaimsQuery;

import java.util.List;

/** The outcome of selecting claims for one {@link HeldCredential} against one Credential Query, per the
 * OpenID4VP 1.1 "Selecting Claims" rules. */
public sealed interface ClaimSelection {

    /** {@code claims} was absent: only mandatory-to-present claims are returned, no claims are
     * selectively disclosed. */
    record MandatoryOnly() implements ClaimSelection {
        public static final MandatoryOnly INSTANCE = new MandatoryOnly();
    }

    /** {@code claims} (optionally with {@code claim_sets}) was satisfied: exactly these Claims Queries'
     * claims are disclosed. */
    record Selected(List<ClaimsQuery> chosenClaims) implements ClaimSelection {
        public Selected {
            chosenClaims = List.copyOf(chosenClaims);
        }
    }
}
