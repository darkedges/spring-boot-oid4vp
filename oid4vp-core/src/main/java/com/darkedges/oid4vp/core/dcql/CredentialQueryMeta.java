package com.darkedges.oid4vp.core.dcql;

/**
 * Marker interface for the format-specific contents of a Credential Query's {@code meta} object.
 *
 * <p>Only {@link SdJwtVcMeta} is used for matching in this phase; the other implementations exist so
 * that queries referencing those formats still parse and round-trip correctly.
 */
public sealed interface CredentialQueryMeta
        permits SdJwtVcMeta, JwtVcMeta, LdpVcMeta, MsoMdocMeta, CredentialQueryMeta.Empty {

    /** An empty {@code meta} object ({@code {}}), valid wherever {@code meta} is present but has no
     * required sub-fields for the given format. */
    record Empty() implements CredentialQueryMeta {
        public static final Empty INSTANCE = new Empty();
    }
}
