package com.darkedges.oid4vp.core.dcql;

import java.util.List;
import java.util.Optional;

/**
 * A DCQL query object: the value of the {@code dcql_query} Authorization Request parameter.
 *
 * @param credentials    REQUIRED non-empty array of Credential Queries.
 * @param credentialSets OPTIONAL non-empty array of Credential Set Queries.
 */
public record DcqlQuery(List<CredentialQuery> credentials, Optional<List<CredentialSetQuery>> credentialSets) {

    public DcqlQuery {
        if (credentials == null || credentials.isEmpty()) {
            throw new IllegalArgumentException("credentials must be a non-empty array");
        }
        credentials = List.copyOf(credentials);
        credentialSets = credentialSets == null ? Optional.empty() : credentialSets.map(List::copyOf);
        DcqlQueryValidator.validate(credentials, credentialSets);
    }

    public static DcqlQuery of(List<CredentialQuery> credentials) {
        return new DcqlQuery(credentials, Optional.empty());
    }

    public static DcqlQuery of(List<CredentialQuery> credentials, List<CredentialSetQuery> credentialSets) {
        return new DcqlQuery(credentials, Optional.ofNullable(credentialSets));
    }

    public Optional<CredentialQuery> findCredential(String id) {
        return credentials.stream().filter(c -> c.id().equals(id)).findFirst();
    }
}
