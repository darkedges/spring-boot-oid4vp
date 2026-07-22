package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.core.dcql.ClaimsQuery;
import com.darkedges.oid4vp.core.dcql.eval.ClaimSelection;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Builds a Wallet-side SD-JWT VC presentation string from a {@link SdJwtVcHeldCredential} and a
 * {@link ClaimSelection} (as produced by {@code DcqlEvaluator}), filtering the issuance-form
 * Disclosures down to exactly what was selected, per OpenID4VP 1.1's "Wallets MUST NOT send selectively
 * disclosable claims that have not been selected" rule.
 */
public final class SdJwtVcPresentationBuilder {

    private SdJwtVcPresentationBuilder() {}

    /** The SD-JWT (issuer JWT + selected disclosures, trailing {@code ~}) without a Key Binding JWT —
     * what's sent when Cryptographic Holder Binding is not required. */
    public static String buildWithoutKeyBinding(SdJwtVcHeldCredential credential, ClaimSelection selection) {
        List<Disclosure> selected = selectDisclosures(credential, selection);
        return new SdJwt(credential.issuanceForm().issuerSignedJwt(), selected, Optional.empty()).toStringWithoutKeyBinding();
    }

    /** The full presentation (SD-JWT + Key Binding JWT), with the KB-JWT signed by {@code holderSigner}
     * and bound to {@code nonce}/{@code aud}. */
    public static String buildWithKeyBinding(
            SdJwtVcHeldCredential credential,
            ClaimSelection selection,
            String nonce,
            String aud,
            Instant iat,
            JWSAlgorithm alg,
            JWSSigner holderSigner) {
        String withoutKeyBinding = buildWithoutKeyBinding(credential, selection);
        SignedJWT kbJwt = KbJwtBuilder.build(
                withoutKeyBinding, nonce, aud, iat, alg, holderSigner, Optional.empty(), Optional.empty());
        return withoutKeyBinding + kbJwt.serialize();
    }

    private static List<Disclosure> selectDisclosures(SdJwtVcHeldCredential credential, ClaimSelection selection) {
        return switch (selection) {
            case ClaimSelection.MandatoryOnly ignored -> List.of();
            case ClaimSelection.Selected(List<ClaimsQuery> chosenClaims) -> {
                Set<Disclosure> needed = new LinkedHashSet<>();
                for (ClaimsQuery claim : chosenClaims) {
                    needed.addAll(credential.disclosuresFor(claim.path()));
                }
                // Preserve original issuance order for a deterministic, natural presentation string.
                yield credential.issuanceForm().disclosures().stream().filter(needed::contains).toList();
            }
        };
    }
}
