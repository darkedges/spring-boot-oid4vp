package com.darkedges.oid4vp.core.response;

import java.util.Optional;

/** A successful OpenID4VP Authorization Response. */
public record AuthorizationResponse(VpToken vpToken, Optional<String> state) {

    public AuthorizationResponse {
        if (vpToken == null) {
            throw new IllegalArgumentException("vp_token is required");
        }
        state = state == null ? Optional.empty() : state;
    }
}
