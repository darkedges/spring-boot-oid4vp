package com.darkedges.oid4vp.spring.security.registration;

import java.net.URI;
import java.util.Optional;

/**
 * Configures a relying-party registration to use the OAuth 2.0 Authorization Code Grant
 * ({@code response_type=code}) instead of the default {@code vp_token} response types — its presence on
 * {@link Oid4vpRelyingPartyRegistration#codeFlow()} is what {@code Oid4vpAuthorizationRequestService}
 * checks to decide which kind of request to build. Per OpenID4VP 1.1, "the VP Token is provided in the
 * Token Response" for this response type, so the Verifier acts as a full OAuth 2.0 client: it redirects
 * the End-User's browser to the Wallet's {@code authorization_endpoint} (PKCE-protected), receives a
 * {@code code} back at {@code redirectUri}, then exchanges it at {@code tokenEndpoint}.
 *
 * @param redirectUri   this Verifier's own callback URL the Wallet redirects the browser back to with
 *                       {@code ?code=...&state=...} — must be served by
 *                       {@code Oid4vpAuthorizationCodeCallbackFilter}. Always required: unlike
 *                       {@code tokenEndpoint}, it never varies per Wallet/test run.
 * @param tokenEndpoint  OPTIONAL: the Wallet's token endpoint, where {@code code} is exchanged for a Token
 *                       Response containing {@code vp_token}. Deliberately independent of
 *                       {@code redirectUri}'s requiredness — this typically starts unset (e.g. only known
 *                       once a conformance test run is started) without that being a configuration error;
 *                       building/hosting the Authorization Request still works with it absent, only the
 *                       eventual code exchange needs it, and fails there with a clear message if it's
 *                       still missing at that point.
 */
public record CodeFlowConfig(URI redirectUri, Optional<URI> tokenEndpoint) {

    public CodeFlowConfig {
        if (redirectUri == null) {
            throw new IllegalArgumentException("redirectUri is required");
        }
        tokenEndpoint = tokenEndpoint == null ? Optional.empty() : tokenEndpoint;
    }
}
