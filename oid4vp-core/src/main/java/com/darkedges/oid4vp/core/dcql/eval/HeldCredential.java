package com.darkedges.oid4vp.core.dcql.eval;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQueryMeta;
import com.darkedges.oid4vp.core.dcql.TrustedAuthoritiesQuery;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * A Credential held by a Wallet, as seen by the {@link DcqlEvaluator}.
 *
 * <p>This abstraction exists so the DCQL evaluator can be exercised in unit tests independently of any
 * real Wallet storage or credential format parsing; the only production implementation in this phase is
 * {@code SdJwtVcHeldCredential} in the {@code oid4vp-format-sdjwt-vc} module.
 */
public interface HeldCredential {

    CredentialFormat format();

    /** The fully-disclosed claim tree this credential currently exposes (selectively-disclosed claims
     * included, since this represents what the Wallet has chosen to reveal to itself, not to a Verifier). */
    JsonNode claimsView();

    /**
     * True iff the claim(s) selected by the given path are selectively disclosable (i.e. the Wallet MAY
     * choose not to present them), as opposed to always mandatorily present.
     */
    boolean isSelectivelyDisclosable(ClaimsPathPointer path);

    /** True iff this credential can be presented with Cryptographic Holder Binding (e.g. has an
     * associated confirmation key and a Key Binding JWT can be produced). */
    boolean hasCryptographicHolderBinding();

    /** True iff this credential's {@code meta} (format-specific type/doctype constraints) matches the
     * given Credential Query {@code meta} object. */
    boolean matchesMeta(CredentialQueryMeta meta);

    /**
     * True iff this credential matches the given Trusted Authorities Query. Not implemented in this
     * phase (Phase 2 concern, requires X.509 chain / federation trust inspection) — defaults to
     * {@code false}, meaning a Credential Query with {@code trusted_authorities} will never match any
     * held credential.
     */
    default boolean matchesTrustedAuthority(TrustedAuthoritiesQuery query) {
        return false;
    }
}
