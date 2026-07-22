package com.darkedges.oid4vp.core.dcql;

/** Thrown when a {@link DcqlQuery} violates one of the cross-field constraints in {@link DcqlQueryValidator}. */
public class DcqlValidationException extends RuntimeException {

    public DcqlValidationException(String message) {
        super(message);
    }
}
