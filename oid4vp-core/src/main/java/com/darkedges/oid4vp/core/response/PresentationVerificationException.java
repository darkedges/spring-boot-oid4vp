package com.darkedges.oid4vp.core.response;

/** A presentation failed format-specific verification (signature, digest, expiry, holder binding, ...). */
public class PresentationVerificationException extends Oid4vpException {

    public PresentationVerificationException(String message) {
        super(Oid4vpErrorCode.ACCESS_DENIED, message);
    }

    public PresentationVerificationException(String message, Throwable cause) {
        super(Oid4vpErrorCode.ACCESS_DENIED, message, cause);
    }
}
