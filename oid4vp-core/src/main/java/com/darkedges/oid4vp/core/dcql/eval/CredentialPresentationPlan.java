package com.darkedges.oid4vp.core.dcql.eval;

/** A single Credential selected to satisfy one Credential Query, together with which claims to disclose. */
public record CredentialPresentationPlan(HeldCredential credential, ClaimSelection claimSelection) {

    public CredentialPresentationPlan {
        if (credential == null || claimSelection == null) {
            throw new IllegalArgumentException("credential and claimSelection are required");
        }
    }
}
