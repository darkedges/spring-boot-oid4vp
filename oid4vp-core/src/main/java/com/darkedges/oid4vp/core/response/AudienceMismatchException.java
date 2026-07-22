package com.darkedges.oid4vp.core.response;

/** The audience bound into a presentation (e.g. a Key Binding JWT's {@code aud}) did not match the
 * expected Client Identifier (or {@code origin:<origin>} for the Digital Credentials API). */
public class AudienceMismatchException extends Oid4vpException {

    public AudienceMismatchException(String expected, String actual) {
        super(Oid4vpErrorCode.ACCESS_DENIED, "audience mismatch: expected \"" + expected + "\", was \"" + actual + "\"");
    }
}
