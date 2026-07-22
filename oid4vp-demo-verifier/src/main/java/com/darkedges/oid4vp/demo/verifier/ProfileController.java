package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** Requires authentication (per {@link SecurityConfig}) — reachable only after a validated OpenID4VP
 * presentation, proving the whole stack (Wallet build → Verifier validate → SecurityContext
 * establishment) actually works end-to-end, not just that the direct_post POST returned 200. */
@RestController
public class ProfileController {

    @GetMapping(value = "/profile", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> profile(Authentication authentication) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (authentication instanceof Oid4vpAuthenticationToken token) {
            Oid4vpPrincipal principal = token.getPrincipal();
            result.put("authenticated", true);
            principal.claim("employee", "given_name").map(JsonNode::asText).ifPresent(v -> result.put("given_name", v));
            principal.claim("employee", "family_name").map(JsonNode::asText).ifPresent(v -> result.put("family_name", v));
        } else {
            result.put("authenticated", false);
        }
        return result;
    }
}
