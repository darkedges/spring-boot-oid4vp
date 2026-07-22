package com.darkedges.oid4vp.core.dcql;

/**
 * Thrown when processing a {@link ClaimsPathPointer} against a credential aborts, per the "abort
 * processing and return an error" steps of the Claims Path Pointer processing algorithm (OpenID4VP
 * 1.1, "Claims Path Pointer" / "Processing").
 */
public class ClaimsPathPointerException extends RuntimeException {

    public ClaimsPathPointerException(String message) {
        super(message);
    }
}
