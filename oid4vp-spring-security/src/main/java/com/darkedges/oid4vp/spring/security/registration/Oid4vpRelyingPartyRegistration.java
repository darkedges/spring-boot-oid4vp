package com.darkedges.oid4vp.spring.security.registration;

import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.ClientMetadata;
import com.darkedges.oid4vp.core.request.RequestUriMethod;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.core.request.VerifierInfoEntry;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * A Verifier's configuration for one Wallet-facing "login option" — analogous to Spring Security's
 * {@code ClientRegistration} for OAuth2/OIDC clients.
 *
 * @param registrationId  a local id used in the response endpoint path, e.g. {@code /login/oid4vp/direct-post/{registrationId}}.
 * @param clientId         this Verifier's own Client Identifier (Prefix + value).
 * @param responseUri      where the Wallet must POST the Authorization Response.
 * @param responseMode     only {@link ResponseMode#DIRECT_POST} is supported in this phase.
 * @param dcqlQuery         supplies the DCQL query for each new Authorization Request (a Supplier so a
 *                         registration can vary the query per-request if desired; most implementations
 *                         will just return a constant).
 * @param clientMetadata    OPTIONAL Verifier metadata to include in the Authorization Request.
 * @param walletAuthorizationEndpoint  OPTIONAL fixed Wallet {@code authorization_endpoint} to redirect
 *                                     the End-User's browser to (see
 *                                     {@code com.darkedges.oid4vp.spring.security.web.Oid4vpWalletInvocationFilter}),
 *                                     for same-device flows toward a Wallet that isn't reached by
 *                                     scanning a QR code or an {@code openid4vp://} deep link — e.g. a
 *                                     web-based Wallet, or a conformance test suite acting as one.
 *                                     Deliberately operator-configured rather than accepted as a request
 *                                     parameter: an attacker-supplied redirect target here would be an
 *                                     open redirect.
 * @param verifierInfo      OPTIONAL {@code verifier_info} attestations to include in the Authorization
 *                          Request (OpenID4VP 1.1 "New Authorization Request Parameters").
 * @param codeFlow          OPTIONAL: when present, this registration uses the OAuth 2.0 Authorization
 *                          Code Grant ({@code response_type=code}) instead of {@code vp_token} — see
 *                          {@link CodeFlowConfig}. {@code responseMode} above is ignored when this is
 *                          present ({@link ResponseMode#QUERY} is used internally).
 * @param requestUriMethod  how a Wallet should fetch {@code request_uri} — {@link RequestUriMethod#GET}
 *                          (the default) or {@link RequestUriMethod#POST}, the latter per OpenID4VP 1.1
 *                          "Request URI Method post". Only affects the actual {@code request_uri_method}
 *                          parameter {@code Oid4vpWalletInvocationFilter} adds to the invoke redirect —
 *                          {@code Oid4vpRequestObjectFilter} already accepts either method regardless.
 */
public record Oid4vpRelyingPartyRegistration(
        String registrationId,
        ClientIdentifierPrefix clientId,
        URI responseUri,
        ResponseMode responseMode,
        Supplier<DcqlQuery> dcqlQuery,
        Optional<ClientMetadata> clientMetadata,
        Optional<URI> walletAuthorizationEndpoint,
        List<VerifierInfoEntry> verifierInfo,
        Optional<CodeFlowConfig> codeFlow,
        RequestUriMethod requestUriMethod) {

    public Oid4vpRelyingPartyRegistration {
        if (registrationId == null || registrationId.isBlank()) {
            throw new IllegalArgumentException("registrationId is required");
        }
        if (clientId == null || responseUri == null || dcqlQuery == null) {
            throw new IllegalArgumentException("clientId, responseUri, and dcqlQuery are required");
        }
        responseMode = responseMode == null ? ResponseMode.DIRECT_POST : responseMode;
        responseMode.requireImplemented();
        clientMetadata = clientMetadata == null ? Optional.empty() : clientMetadata;
        walletAuthorizationEndpoint = walletAuthorizationEndpoint == null ? Optional.empty() : walletAuthorizationEndpoint;
        verifierInfo = verifierInfo == null ? List.of() : List.copyOf(verifierInfo);
        codeFlow = codeFlow == null ? Optional.empty() : codeFlow;
        requestUriMethod = requestUriMethod == null ? RequestUriMethod.GET : requestUriMethod;
    }
}
