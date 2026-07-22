package com.darkedges.oid4vp.core.dcql.eval;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQueryMeta;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * A synthetic {@code dc+sd-jwt} {@link HeldCredential} test double, so {@link DcqlEvaluator} can be
 * exercised without any real SD-JWT parsing/crypto. {@link #isSelectivelyDisclosable} is not consulted
 * by the evaluator itself (it exists for a future presentation-builder step), so this double always
 * answers {@code true}.
 */
record TestHeldCredential(String vct, JsonNode claims, boolean holderBinding) implements HeldCredential {

    @Override
    public CredentialFormat format() {
        return CredentialFormat.DC_SD_JWT;
    }

    @Override
    public JsonNode claimsView() {
        return claims;
    }

    @Override
    public boolean isSelectivelyDisclosable(ClaimsPathPointer path) {
        return true;
    }

    @Override
    public boolean hasCryptographicHolderBinding() {
        return holderBinding;
    }

    @Override
    public boolean matchesMeta(CredentialQueryMeta meta) {
        return meta instanceof SdJwtVcMeta sdJwtVcMeta && sdJwtVcMeta.vctValues().contains(vct);
    }
}
