package com.darkedges.oid4vp.core.dcql;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Credential Format Identifier, as used in the {@code format} member of a Credential Query and in
 * {@code vp_formats_supported}.
 *
 * <p>Only {@link #DC_SD_JWT} has a matcher/verifier implementation in this phase of the project; the
 * other formats are modeled so that DCQL queries and metadata referencing them still parse correctly,
 * but any attempt to actually evaluate or verify a presentation in one of those formats will simply
 * find no registered matcher/verifier.
 */
public enum CredentialFormat {
    DC_SD_JWT("dc+sd-jwt"),
    JWT_VC_JSON("jwt_vc_json"),
    LDP_VC("ldp_vc"),
    MSO_MDOC("mso_mdoc");

    private final String identifier;

    CredentialFormat(String identifier) {
        this.identifier = identifier;
    }

    @JsonValue
    public String identifier() {
        return identifier;
    }

    @JsonCreator
    public static CredentialFormat fromIdentifier(String identifier) {
        for (CredentialFormat format : values()) {
            if (format.identifier.equals(identifier)) {
                return format;
            }
        }
        throw new IllegalArgumentException("Unknown Credential Format Identifier: " + identifier);
    }

    @Override
    public String toString() {
        return identifier;
    }
}
