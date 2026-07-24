package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.request.AuthorizationRequestWriter;
import com.darkedges.oid4vp.core.request.ExpectedAudienceResolver;
import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestResolution;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestService;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes a fresh Authorization Request as JSON — in a real deployment this would instead be encoded
 * into a QR code / {@code openid4vp://} deep link for the Wallet to invoke; the demo just serves it
 * directly so the demo Wallet app can fetch and act on it over HTTP.
 *
 * <p>Serialized manually via {@code ObjectNode.toString()} rather than returned directly: Spring MVC's
 * autoconfigured Jackson converter introspects {@link ObjectNode} as a bean (its {@code isXxx()} tree-type
 * predicate methods look like getters) instead of using Jackson's dedicated {@code JsonNode} tree
 * serializer, unless the value is pre-serialized to a plain {@code String}.
 *
 * <p>Also adds a bespoke {@code expected_response_audience} field, not part of the JSON shape a real
 * Authorization Request would have: this endpoint is unsigned, so unlike a real Wallet fetching a signed
 * {@code request_uri}, the demo Wallet fetching this never sees the request-signing certificate's {@code
 * x5c} chain — it has no way to independently compute the {@code x509_hash:...} audience an
 * {@code x509_san_dns} registration's response must be bound to (see {@link ExpectedAudienceResolver}).
 * Telling it the precomputed value directly is only safe because this whole endpoint is already a
 * demo-only convenience shortcut, not a real protocol surface.
 */
@RestController
public class AuthorizeController {

    private final Oid4vpAuthorizationRequestService requestService;
    private final RequestObjectSigningKeyResolver requestObjectSigningKeyResolver;

    public AuthorizeController(
            Oid4vpAuthorizationRequestService requestService,
            RequestObjectSigningKeyResolver requestObjectSigningKeyResolver) {
        this.requestService = requestService;
        this.requestObjectSigningKeyResolver = requestObjectSigningKeyResolver;
    }

    @GetMapping(value = "/oid4vp/authorize/{registrationId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public String authorize(@PathVariable String registrationId) {
        Oid4vpAuthorizationRequestResolution resolution = requestService.resolve(registrationId);
        ObjectNode json = AuthorizationRequestWriter.write(resolution.request());
        json.put("transaction_id", resolution.transactionId());
        json.put("expected_response_audience", ExpectedAudienceResolver.resolve(
                resolution.request().clientId(), requestObjectSigningKeyResolver, registrationId));
        return json.toString();
    }
}
