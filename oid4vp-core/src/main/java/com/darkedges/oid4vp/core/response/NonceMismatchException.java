package com.darkedges.oid4vp.core.response;

/** The {@code nonce} bound into a presentation (e.g. a Key Binding JWT's {@code nonce}) did not match
 * the Authorization Request's {@code nonce}. */
public class NonceMismatchException extends Oid4vpException {

    public NonceMismatchException(String expected, String actual) {
        super(Oid4vpErrorCode.ACCESS_DENIED, "nonce mismatch: expected \"" + expected + "\", was \"" + actual + "\"");
    }
}
