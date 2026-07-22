package com.darkedges.oid4vp.demo.wallet;

/** Values that must match between the demo Wallet and demo Verifier apps — in a real deployment these
 * would be discovered (via DCQL {@code vct_values} in the request, and Issuer trust configuration), not
 * hardcoded; the demo hardcodes them on both sides for simplicity. */
public final class DemoConstants {

    public static final String VCT = "https://demo.oid4vp.example/employee_credential";

    private DemoConstants() {}
}
