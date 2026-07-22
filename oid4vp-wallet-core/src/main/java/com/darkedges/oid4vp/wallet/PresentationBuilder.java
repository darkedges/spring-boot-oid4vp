package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.eval.CredentialPresentationPlan;
import com.darkedges.oid4vp.core.response.PresentationEntry;

/**
 * Format-specific Wallet-side presentation-building SPI. One implementation per {@link CredentialFormat};
 * in this phase, only {@code dc+sd-jwt} has one ({@link SdJwtVcPresentationBuilderAdapter}).
 */
public interface PresentationBuilder {

    CredentialFormat format();

    /** Builds one Presentation for the given selected credential + claim selection, per
     * {@link PresentationBuildParams}. */
    PresentationEntry build(CredentialPresentationPlan plan, PresentationBuildParams params);
}
