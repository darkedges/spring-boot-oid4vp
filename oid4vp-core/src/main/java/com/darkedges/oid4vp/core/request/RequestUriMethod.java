package com.darkedges.oid4vp.core.request;

/**
 * The {@code request_uri_method} Authorization Request parameter (OpenID4VP 1.1, "Request URI Method
 * post"). Case-sensitive: any value other than exactly {@code "get"} or {@code "post"} is an
 * {@code invalid_request_uri_method} error.
 */
public enum RequestUriMethod {
    GET("get"),
    POST("post");

    private final String value;

    RequestUriMethod(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    /** @throws InvalidRequestUriMethodException if value is anything other than exactly "get"/"post". */
    public static RequestUriMethod parse(String value) {
        if (GET.value.equals(value)) {
            return GET;
        }
        if (POST.value.equals(value)) {
            return POST;
        }
        throw new InvalidRequestUriMethodException(value);
    }

    public static class InvalidRequestUriMethodException extends RuntimeException {
        public InvalidRequestUriMethodException(String value) {
            super("invalid request_uri_method (must be exactly \"get\" or \"post\"): " + value);
        }
    }
}
