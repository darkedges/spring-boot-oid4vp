package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.request.AuthorizationRequestWriter;
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
 */
@RestController
public class AuthorizeController {

    private final Oid4vpAuthorizationRequestService requestService;

    public AuthorizeController(Oid4vpAuthorizationRequestService requestService) {
        this.requestService = requestService;
    }

    @GetMapping(value = "/oid4vp/authorize/{registrationId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public String authorize(@PathVariable String registrationId) {
        Oid4vpAuthorizationRequestResolution resolution = requestService.resolve(registrationId);
        ObjectNode json = AuthorizationRequestWriter.write(resolution.request());
        json.put("transaction_id", resolution.transactionId());
        return json.toString();
    }
}
