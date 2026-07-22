package com.darkedges.oid4vp.verifier;

import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.CredentialSetQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import com.darkedges.oid4vp.core.response.Oid4vpException;
import com.darkedges.oid4vp.core.response.VpToken;

import java.util.Set;

/**
 * Checks that a returned {@link VpToken} <em>structurally</em> satisfies the {@link DcqlQuery} it is
 * answering (OpenID4VP 1.1, "Selecting Credentials") — i.e. that every required Credential Query /
 * Credential Set Query has a corresponding entry, and that {@code multiple: false} queries got exactly
 * one Presentation. This does not re-run claim-level selection against the verified presentation
 * contents (that would duplicate the {@code DcqlEvaluator}'s Wallet-side logic on the Verifier side); it
 * only checks the shape of the response against the shape of the request.
 */
final class DcqlResponseValidator {

    private DcqlResponseValidator() {}

    static void validate(DcqlQuery query, VpToken vpToken) {
        Set<String> presentIds = vpToken.presentations().keySet();

        if (query.credentialSets().isEmpty()) {
            for (CredentialQuery credentialQuery : query.credentials()) {
                if (!presentIds.contains(credentialQuery.id())) {
                    throw new Oid4vpException(Oid4vpErrorCode.ACCESS_DENIED,
                            "vp_token is missing required credential query: \"" + credentialQuery.id() + "\"");
                }
            }
        } else {
            for (CredentialSetQuery set : query.credentialSets().get()) {
                boolean satisfied = set.options().stream().anyMatch(presentIds::containsAll);
                if (!satisfied && set.required()) {
                    throw new Oid4vpException(Oid4vpErrorCode.ACCESS_DENIED,
                            "vp_token does not satisfy required credential_sets entry: options=" + set.options());
                }
            }
        }

        for (CredentialQuery credentialQuery : query.credentials()) {
            if (!credentialQuery.multiple() && presentIds.contains(credentialQuery.id())) {
                int count = vpToken.get(credentialQuery.id()).orElseThrow().size();
                if (count != 1) {
                    throw new Oid4vpException(Oid4vpErrorCode.ACCESS_DENIED,
                            "credential query \"" + credentialQuery.id() + "\" does not allow multiple Presentations, got " + count);
                }
            }
        }
    }
}
