package com.darkedges.oid4vp.core.dcql;

/**
 * {@code meta} object for an {@code mso_mdoc} Credential Query. Parse-only stub in this phase (no
 * {@code mso_mdoc} {@link com.darkedges.oid4vp.core.dcql.eval.CredentialQueryMatcher} is registered).
 *
 * @param doctypeValue REQUIRED ISO mdoc doctype value.
 */
public record MsoMdocMeta(String doctypeValue) implements CredentialQueryMeta {

    public MsoMdocMeta {
        if (doctypeValue == null || doctypeValue.isBlank()) {
            throw new IllegalArgumentException("doctype_value is required");
        }
    }
}
