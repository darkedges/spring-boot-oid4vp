package com.darkedges.oid4vp.core.request;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;

/**
 * Exchanges an OAuth 2.0 authorization {@code code} for a Token Response at a Wallet's token endpoint —
 * the final step of the Authorization Code Grant ({@code response_type=code}), per OpenID4VP 1.1: "the VP
 * Token is provided in the Token Response." Kept transport-agnostic here (this module has no HTTP client
 * dependency); the real implementation (a plain PKCE token exchange POST) lives at the application edge,
 * same as {@link com.darkedges.oid4vp.core.response.IssuerKeyResolver}.
 */
public interface TokenEndpointClient {

    /**
     * @param codeVerifier the PKCE code verifier generated when the Authorization Request was built (see
     *                     {@code Oid4vpAuthorizationRequestContext.codeVerifier()}), sent so the token
     *                     endpoint can verify it against the {@code code_challenge} sent earlier.
     * @return the parsed JSON Token Response body; the caller reads its {@code vp_token} member.
     */
    JsonNode exchange(URI tokenEndpoint, String code, String redirectUri, String clientId, String codeVerifier);
}
