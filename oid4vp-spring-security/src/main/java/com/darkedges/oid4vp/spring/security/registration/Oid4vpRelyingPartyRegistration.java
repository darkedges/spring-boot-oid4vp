package com.darkedges.oid4vp.spring.security.registration;

import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.ClientMetadata;
import com.darkedges.oid4vp.core.request.ResponseMode;

import java.net.URI;
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
 */
public record Oid4vpRelyingPartyRegistration(
        String registrationId,
        ClientIdentifierPrefix clientId,
        URI responseUri,
        ResponseMode responseMode,
        Supplier<DcqlQuery> dcqlQuery,
        Optional<ClientMetadata> clientMetadata) {

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
    }
}
