package com.darkedges.oid4vp.spring.security.authentication;

import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import org.springframework.security.core.AuthenticationException;

/** Wraps an {@link Oid4vpErrorCode} as a Spring Security {@link AuthenticationException}. */
public class Oid4vpAuthenticationException extends AuthenticationException {

    private final Oid4vpErrorCode errorCode;

    public Oid4vpAuthenticationException(Oid4vpErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public Oid4vpAuthenticationException(Oid4vpErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public Oid4vpErrorCode errorCode() {
        return errorCode;
    }
}
