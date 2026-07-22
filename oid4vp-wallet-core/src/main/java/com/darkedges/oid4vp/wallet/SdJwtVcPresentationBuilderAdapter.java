package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.eval.CredentialPresentationPlan;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.sdjwt.SdJwtVcHeldCredential;
import com.darkedges.oid4vp.sdjwt.SdJwtVcPresentationBuilder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;

/** Adapts {@link SdJwtVcPresentationBuilder} to the format-agnostic {@link PresentationBuilder} SPI. */
public final class SdJwtVcPresentationBuilderAdapter implements PresentationBuilder {

    private final JWSAlgorithm keyBindingAlgorithm;

    public SdJwtVcPresentationBuilderAdapter(JWSAlgorithm keyBindingAlgorithm) {
        this.keyBindingAlgorithm = keyBindingAlgorithm;
    }

    public SdJwtVcPresentationBuilderAdapter() {
        this(JWSAlgorithm.ES256);
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.DC_SD_JWT;
    }

    @Override
    public PresentationEntry build(CredentialPresentationPlan plan, PresentationBuildParams params) {
        HeldCredential credential = plan.credential();
        if (!(credential instanceof SdJwtVcHeldCredential sdJwtVcHeldCredential)) {
            throw new IllegalArgumentException(
                    "SdJwtVcPresentationBuilderAdapter requires a SdJwtVcHeldCredential, was: " + credential.getClass());
        }

        if (!sdJwtVcHeldCredential.hasCryptographicHolderBinding()) {
            String presentation = SdJwtVcPresentationBuilder.buildWithoutKeyBinding(sdJwtVcHeldCredential, plan.claimSelection());
            return new PresentationEntry.StringPresentation(presentation);
        }

        JWSSigner signer = params.holderKeyResolver().resolveSigner(sdJwtVcHeldCredential)
                .orElseThrow(() -> new IllegalStateException("no holder signer available for this credential's Holder Binding key"));
        String presentation = SdJwtVcPresentationBuilder.buildWithKeyBinding(
                sdJwtVcHeldCredential, plan.claimSelection(), params.nonce(), params.audience(),
                params.clock().instant(), keyBindingAlgorithm, signer);
        return new PresentationEntry.StringPresentation(presentation);
    }
}
