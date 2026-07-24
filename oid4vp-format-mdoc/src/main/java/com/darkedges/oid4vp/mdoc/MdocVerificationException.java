package com.darkedges.oid4vp.mdoc;

import com.darkedges.oid4vp.core.response.PresentationVerificationException;

/** An ISO mdoc {@code DeviceResponse} (or one of its documents) failed verification. */
public class MdocVerificationException extends PresentationVerificationException {

    public MdocVerificationException(String message) {
        super(message);
    }

    public MdocVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
