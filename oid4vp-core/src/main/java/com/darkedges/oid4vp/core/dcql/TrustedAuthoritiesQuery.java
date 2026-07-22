package com.darkedges.oid4vp.core.dcql;

import java.util.List;

/**
 * A Trusted Authorities Query object: one entry in a Credential Query's {@code trusted_authorities}
 * array.
 *
 * @param type   REQUIRED type of information conveyed by {@code values}.
 * @param values REQUIRED non-empty array of trusted authority identifiers, meaning depends on {@code type}.
 */
public record TrustedAuthoritiesQuery(TrustedAuthorityType type, List<String> values) {

    public TrustedAuthoritiesQuery {
        if (type == null) {
            throw new IllegalArgumentException("type is required");
        }
        if (values == null || values.isEmpty()) {
            throw new IllegalArgumentException("values must be a non-empty array");
        }
        values = List.copyOf(values);
    }
}
