package com.darkedges.oid4vp.core.dcql;

import java.util.List;

/**
 * {@code meta} object for an {@code ldp_vc} Credential Query. Parse-only stub in this phase (no
 * {@code ldp_vc} {@link com.darkedges.oid4vp.core.dcql.eval.CredentialQueryMatcher} is registered).
 *
 * @param typeValues REQUIRED array-of-arrays of expanded (JSON-LD {@code @context}-expanded) type IRIs.
 */
public record LdpVcMeta(List<List<String>> typeValues) implements CredentialQueryMeta {

    public LdpVcMeta {
        if (typeValues == null || typeValues.isEmpty()) {
            throw new IllegalArgumentException("type_values must be a non-empty array");
        }
        typeValues = List.copyOf(typeValues);
    }
}
