package com.darkedges.oid4vp.core.dcql;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The {@code type} of a Trusted Authorities Query (OpenID4VP 1.1, "Trusted Authorities Query").
 *
 * <p>Resolution against these types (Authority Key Identifier matching, ETSI Trusted List lookup,
 * OpenID Federation trust path construction) is not implemented in this phase; only the model/parsing
 * is provided.
 */
public enum TrustedAuthorityType {
    AKI("aki"),
    ETSI_TL("etsi_tl"),
    OPENID_FEDERATION("openid_federation");

    private final String value;

    TrustedAuthorityType(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static TrustedAuthorityType fromValue(String value) {
        for (TrustedAuthorityType type : values()) {
            if (type.value.equals(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown trusted authority type: " + value);
    }

    @Override
    public String toString() {
        return value;
    }
}
