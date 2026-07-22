package com.darkedges.oid4vp.jwtvcjson;

import com.darkedges.oid4vp.core.response.PresentationVerificationException;

/** A {@code jwt_vc_json} Verifiable Presentation (or the Verifiable Credential it wraps) failed
 * verification. */
public class JwtVcJsonVerificationException extends PresentationVerificationException {

    public JwtVcJsonVerificationException(String message) {
        super(message);
    }

    public JwtVcJsonVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
