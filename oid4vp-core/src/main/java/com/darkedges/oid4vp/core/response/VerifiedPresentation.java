package com.darkedges.oid4vp.core.response;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Optional;

/**
 * The result of successfully verifying one presentation: its (digest-verified, where applicable)
 * disclosed claims.
 *
 * @param credentialQueryId the {@code vp_token} key this presentation was returned under.
 * @param format            the Credential Format that was verified.
 * @param verifiedClaims    the verified claim tree (e.g. for {@code dc+sd-jwt}, the reconstructed
 *                          payload with disclosed selectively-disclosable claims merged in).
 * @param holderKeyConfirmed the holder's confirmation key (raw JWK JSON), present iff Cryptographic
 *                          Holder Binding was verified for this presentation.
 */
public record VerifiedPresentation(
        String credentialQueryId, CredentialFormat format, JsonNode verifiedClaims, Optional<JsonNode> holderKeyConfirmed) {

    public VerifiedPresentation {
        if (credentialQueryId == null || format == null || verifiedClaims == null) {
            throw new IllegalArgumentException("credentialQueryId, format, and verifiedClaims are required");
        }
        holderKeyConfirmed = holderKeyConfirmed == null ? Optional.empty() : holderKeyConfirmed;
    }
}
