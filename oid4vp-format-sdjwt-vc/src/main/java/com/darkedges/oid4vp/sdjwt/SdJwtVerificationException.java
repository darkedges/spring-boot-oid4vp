package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.core.response.PresentationVerificationException;

/** An SD-JWT VC (or its Key Binding JWT) failed verification. */
public class SdJwtVerificationException extends PresentationVerificationException {

    public SdJwtVerificationException(String message) {
        super(message);
    }

    public SdJwtVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
