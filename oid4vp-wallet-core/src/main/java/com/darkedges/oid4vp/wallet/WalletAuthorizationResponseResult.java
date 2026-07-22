package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.core.response.VpToken;

/** The outcome of evaluating an Authorization Request's DCQL query and attempting to build a response. */
public sealed interface WalletAuthorizationResponseResult {

    record Built(VpToken vpToken) implements WalletAuthorizationResponseResult {}

    /** The DCQL query could not be satisfied by anything in the Wallet's {@code CredentialStore} —
     * corresponds to the Wallet returning an {@code access_denied} error. */
    record Declined(String reason) implements WalletAuthorizationResponseResult {}
}
