package com.darkedges.oid4vp.core.dcql;

import java.util.List;

/**
 * {@code meta} object for a {@code dc+sd-jwt} Credential Query.
 *
 * @param vctValues REQUIRED non-empty array of acceptable {@code vct} type identifiers. Type Metadata
 *                  inheritance ("Wallet MAY return Credentials that inherit from any of the specified
 *                  types") is not resolved in this phase — matching is exact-value only.
 */
public record SdJwtVcMeta(List<String> vctValues) implements CredentialQueryMeta {

    public SdJwtVcMeta {
        if (vctValues == null || vctValues.isEmpty()) {
            throw new IllegalArgumentException("vct_values must be a non-empty array");
        }
        vctValues = List.copyOf(vctValues);
    }
}
