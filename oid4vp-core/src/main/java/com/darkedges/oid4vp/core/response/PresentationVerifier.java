package com.darkedges.oid4vp.core.response;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;

/**
 * Format-specific presentation verification SPI. One implementation per {@link CredentialFormat}; in
 * this phase, only {@code dc+sd-jwt} has one (in the {@code oid4vp-format-sdjwt-vc} module).
 */
public interface PresentationVerifier {

    CredentialFormat format();

    /**
     * Verifies a single presentation string/object and returns its verified claims.
     *
     * @throws PresentationVerificationException on any verification failure (signature, digest,
     *                                            expiry, or holder binding).
     * @throws NonceMismatchException            if the presentation's bound nonce doesn't match.
     * @throws AudienceMismatchException         if the presentation's bound audience doesn't match.
     */
    VerifiedPresentation verify(PresentationEntry presentation, PresentationVerificationParams params);
}
