package com.darkedges.oid4vp.core.request;

import com.darkedges.oid4vp.core.dcql.DcqlQuery;

import java.util.List;
import java.util.Optional;

/**
 * An OpenID4VP Authorization Request.
 *
 * <p>Only the fields needed to build and validate a {@code direct_post} request/response round-trip in
 * this phase are fully enforced; other response modes are modeled but {@link ResponseMode#requireImplemented()}
 * will reject their actual use elsewhere in the stack.
 */
public record AuthorizationRequest(
        String responseType,
        ClientIdentifierPrefix clientId,
        ResponseMode responseMode,
        Optional<String> responseUri,
        Optional<String> redirectUri,
        Optional<DcqlQuery> dcqlQuery,
        Optional<String> scope,
        Optional<String> state,
        String nonce,
        Optional<ClientMetadata> clientMetadata,
        RequestUriMethod requestUriMethod,
        List<TransactionDataEntry> transactionData,
        List<VerifierInfoEntry> verifierInfo) {

    public AuthorizationRequest {
        if (responseType == null || responseType.isBlank()) {
            throw new IllegalArgumentException("response_type is required");
        }
        if (clientId == null) {
            throw new IllegalArgumentException("client_id is required");
        }
        if (responseMode == null) {
            throw new IllegalArgumentException("response_mode is required");
        }
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalArgumentException("nonce is required");
        }
        responseUri = responseUri == null ? Optional.empty() : responseUri;
        redirectUri = redirectUri == null ? Optional.empty() : redirectUri;
        dcqlQuery = dcqlQuery == null ? Optional.empty() : dcqlQuery;
        scope = scope == null ? Optional.empty() : scope;
        state = state == null ? Optional.empty() : state;
        clientMetadata = clientMetadata == null ? Optional.empty() : clientMetadata;
        requestUriMethod = requestUriMethod == null ? RequestUriMethod.GET : requestUriMethod;
        transactionData = transactionData == null ? List.of() : List.copyOf(transactionData);
        verifierInfo = verifierInfo == null ? List.of() : List.copyOf(verifierInfo);

        if (dcqlQuery.isPresent() == scope.isPresent()) {
            throw new IllegalArgumentException("exactly one of dcql_query or scope (as a DCQL query alias) must be present");
        }
        if (responseMode == ResponseMode.DIRECT_POST || responseMode == ResponseMode.DIRECT_POST_JWT) {
            if (responseUri.isEmpty()) {
                throw new IllegalArgumentException("response_uri is required when response_mode is " + responseMode);
            }
            if (redirectUri.isPresent()) {
                throw new IllegalArgumentException("redirect_uri MUST NOT be present when response_mode is " + responseMode);
            }
        }
    }
}
