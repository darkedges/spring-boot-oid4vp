package com.darkedges.oid4vp.core.response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** OpenID4VP 1.1 {@code error} codes (OAuth2 error response, "Error Response"). */
public enum Oid4vpErrorCode {
    INVALID_REQUEST("invalid_request"),
    INVALID_CLIENT("invalid_client"),
    ACCESS_DENIED("access_denied"),
    VP_FORMATS_NOT_SUPPORTED("vp_formats_not_supported"),
    INVALID_REQUEST_URI_METHOD("invalid_request_uri_method"),
    INVALID_TRANSACTION_DATA("invalid_transaction_data"),
    WALLET_UNAVAILABLE("wallet_unavailable");

    private final String value;

    Oid4vpErrorCode(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static Oid4vpErrorCode fromValue(String value) {
        for (Oid4vpErrorCode code : values()) {
            if (code.value.equals(value)) {
                return code;
            }
        }
        throw new IllegalArgumentException("Unknown OpenID4VP error code: " + value);
    }

    @Override
    public String toString() {
        return value;
    }
}
