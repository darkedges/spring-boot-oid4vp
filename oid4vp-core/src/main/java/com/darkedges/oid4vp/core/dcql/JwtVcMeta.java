package com.darkedges.oid4vp.core.dcql;

import java.util.List;

/**
 * {@code meta} object for a {@code jwt_vc_json} Credential Query. Parse-only stub in this phase (no
 * {@code jwt_vc_json} {@link com.darkedges.oid4vp.core.dcql.eval.CredentialQueryMatcher} is registered).
 *
 * @param typeValues REQUIRED array-of-arrays of expanded (JSON-LD {@code @context}-expanded) type IRIs.
 */
public record JwtVcMeta(List<List<String>> typeValues) implements CredentialQueryMeta {

    public JwtVcMeta {
        if (typeValues == null || typeValues.isEmpty()) {
            throw new IllegalArgumentException("type_values must be a non-empty array");
        }
        typeValues = List.copyOf(typeValues);
    }
}
