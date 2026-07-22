package com.darkedges.oid4vp.core.dcql;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Cross-field validation of a {@link DcqlQuery}, beyond what each record's compact constructor already
 * enforces on its own fields.
 */
final class DcqlQueryValidator {

    private DcqlQueryValidator() {}

    static void validate(List<CredentialQuery> credentials, Optional<List<CredentialSetQuery>> credentialSets) {
        Set<String> credentialIds = new HashSet<>();
        for (CredentialQuery credential : credentials) {
            if (!credentialIds.add(credential.id())) {
                throw new DcqlValidationException("duplicate credential query id: " + credential.id());
            }
            validateClaims(credential);
        }

        credentialSets.ifPresent(sets -> {
            for (CredentialSetQuery set : sets) {
                for (List<String> option : set.options()) {
                    for (String referencedId : option) {
                        if (!credentialIds.contains(referencedId)) {
                            throw new DcqlValidationException(
                                    "credential_sets option references unknown credential query id: " + referencedId);
                        }
                    }
                }
            }
        });
    }

    private static void validateClaims(CredentialQuery credential) {
        boolean hasClaimSets = credential.claimSets().isPresent();
        if (hasClaimSets && credential.claims().isEmpty()) {
            throw new DcqlValidationException(
                    "credential query \"" + credential.id() + "\": claim_sets MUST NOT be present if claims is absent");
        }

        Set<String> claimIds = new HashSet<>();
        credential.claims().ifPresent(claims -> {
            for (ClaimsQuery claim : claims) {
                if (hasClaimSets && claim.id().isEmpty()) {
                    throw new DcqlValidationException(
                            "credential query \"" + credential.id() + "\": claim id is required when claim_sets is present");
                }
                claim.id().ifPresent(id -> {
                    if (!claimIds.add(id)) {
                        throw new DcqlValidationException(
                                "credential query \"" + credential.id() + "\": duplicate claim id: " + id);
                    }
                });
            }
        });

        credential.claimSets().ifPresent(sets -> {
            for (List<String> option : sets) {
                for (String referencedClaimId : option) {
                    if (!claimIds.contains(referencedClaimId)) {
                        throw new DcqlValidationException("credential query \"" + credential.id()
                                + "\": claim_sets references unknown claim id: " + referencedClaimId);
                    }
                }
            }
        });
    }
}
