package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.eval.CredentialPresentationPlan;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.mdoc.MdocHeldCredential;
import com.darkedges.oid4vp.mdoc.MdocPresentationBuilder;

import java.security.PrivateKey;

/** Adapts {@link MdocPresentationBuilder} to the format-agnostic {@link PresentationBuilder} SPI. */
public final class MdocPresentationBuilderAdapter implements PresentationBuilder {

    @Override
    public CredentialFormat format() {
        return CredentialFormat.MSO_MDOC;
    }

    @Override
    public PresentationEntry build(CredentialPresentationPlan plan, PresentationBuildParams params) {
        HeldCredential credential = plan.credential();
        if (!(credential instanceof MdocHeldCredential mdocHeldCredential)) {
            throw new IllegalArgumentException(
                    "MdocPresentationBuilderAdapter requires a MdocHeldCredential, was: " + credential.getClass());
        }

        PrivateKey devicePrivateKey = params.holderKeyResolver().resolvePrivateKey(mdocHeldCredential)
                .orElseThrow(() -> new IllegalStateException("no device private key available for this mdoc credential"));

        String presentation = MdocPresentationBuilder.build(
                mdocHeldCredential, plan.claimSelection(), devicePrivateKey,
                params.clientId(), params.responseUri(), params.nonce(), params.responseEncryptionPublicJwk());
        return new PresentationEntry.StringPresentation(presentation);
    }
}
