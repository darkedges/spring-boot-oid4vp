package com.darkedges.oid4vp.core.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The {@code response_mode} Authorization Request parameter. {@link #FRAGMENT} and {@link #QUERY} are
 * modeled only for completeness of the OAuth default (this library targets Verifier-initiated
 * {@code vp_token} flows, not browser-redirect response delivery) — {@link #requireImplemented()} throws
 * for them.
 */
public enum ResponseMode {
    FRAGMENT("fragment"),
    QUERY("query"),
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt"),
    DC_API("dc_api"),
    DC_API_JWT("dc_api.jwt");

    private final String value;

    ResponseMode(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static ResponseMode fromValue(String value) {
        for (ResponseMode mode : values()) {
            if (mode.value.equals(value)) {
                return mode;
            }
        }
        throw new IllegalArgumentException("Unknown response_mode: " + value);
    }

    public boolean isImplemented() {
        return this == DIRECT_POST || this == DIRECT_POST_JWT || this == DC_API || this == DC_API_JWT;
    }

    /** @throws UnsupportedOperationException if this response mode is not yet implemented. */
    public void requireImplemented() {
        if (!isImplemented()) {
            throw new UnsupportedOperationException("response_mode \"" + value + "\" is not implemented");
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
