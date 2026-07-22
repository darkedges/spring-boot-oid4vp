package com.darkedges.oid4vp.core.response;

import java.util.Optional;

/** An OpenID4VP Authorization Error Response. */
public record AuthorizationErrorResponse(
        Oid4vpErrorCode error, Optional<String> errorDescription, Optional<String> state) {

    public AuthorizationErrorResponse {
        if (error == null) {
            throw new IllegalArgumentException("error is required");
        }
        errorDescription = errorDescription == null ? Optional.empty() : errorDescription;
        state = state == null ? Optional.empty() : state;
    }

    public static AuthorizationErrorResponse of(Oid4vpErrorCode error, String description) {
        return new AuthorizationErrorResponse(error, Optional.ofNullable(description), Optional.empty());
    }
}
