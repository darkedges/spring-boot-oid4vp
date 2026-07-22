package com.darkedges.oid4vp.verifier;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import com.darkedges.oid4vp.core.response.Oid4vpException;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.PresentationVerificationParams;
import com.darkedges.oid4vp.core.response.PresentationVerifier;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.core.response.VpToken;

import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates a full Authorization Response's {@code vp_token} against the {@link DcqlQuery} it is
 * answering: checks the response's shape via {@link DcqlResponseValidator}, then dispatches each
 * Presentation to the registered format-specific {@link PresentationVerifier}, binding every
 * presentation to the same {@code nonce}/audience.
 */
public final class AuthorizationResponseValidator {

    private final Map<CredentialFormat, PresentationVerifier> verifiers;

    public AuthorizationResponseValidator(Map<CredentialFormat, PresentationVerifier> verifiers) {
        this.verifiers = Map.copyOf(verifiers);
    }

    public Map<String, List<VerifiedPresentation>> validate(
            DcqlQuery query,
            VpToken vpToken,
            String expectedNonce,
            String expectedAudience,
            IssuerKeyResolver issuerKeyResolver,
            Clock clock) {
        DcqlResponseValidator.validate(query, vpToken);

        Map<String, List<VerifiedPresentation>> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<PresentationEntry>> entry : vpToken.presentations().entrySet()) {
            String credentialQueryId = entry.getKey();
            CredentialQuery credentialQuery = query.findCredential(credentialQueryId)
                    .orElseThrow(() -> new Oid4vpException(Oid4vpErrorCode.INVALID_REQUEST,
                            "vp_token references unknown credential query id: \"" + credentialQueryId + "\""));

            PresentationVerifier verifier = verifiers.get(credentialQuery.format());
            if (verifier == null) {
                throw new Oid4vpException(Oid4vpErrorCode.VP_FORMATS_NOT_SUPPORTED,
                        "no PresentationVerifier registered for format: " + credentialQuery.format());
            }

            PresentationVerificationParams params =
                    new PresentationVerificationParams(credentialQuery, expectedNonce, expectedAudience, issuerKeyResolver, clock);

            List<VerifiedPresentation> verified = new ArrayList<>();
            for (PresentationEntry presentationEntry : entry.getValue()) {
                verified.add(verifier.verify(presentationEntry, params));
            }
            result.put(credentialQueryId, verified);
        }
        return result;
    }
}
