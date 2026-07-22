package com.darkedges.oid4vp.core.response;

/** Base class for exceptions that carry an {@link Oid4vpErrorCode} for the Error Response. */
public class Oid4vpException extends RuntimeException {

    private final Oid4vpErrorCode errorCode;

    public Oid4vpException(Oid4vpErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public Oid4vpException(Oid4vpErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public Oid4vpErrorCode errorCode() {
        return errorCode;
    }
}
