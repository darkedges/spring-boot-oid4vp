package com.darkedges.oid4vp.core.dcql;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Credential Format Identifier, as used in the {@code format} member of a Credential Query and in
 * {@code vp_formats_supported}.
 *
 * <p>Only {@link #DC_SD_JWT} has a matcher/verifier implementation in this phase of the project; the
 * other formats are modeled so that DCQL queries and metadata referencing them still parse correctly,
 * but any attempt to actually evaluate or verify a presentation in one of those formats will simply
 * find no registered matcher/verifier.
 *
 * <p>{@link #DC_SD_JWT} also recognizes {@code vc+sd-jwt} when parsing ({@link #fromIdentifier}):
 * OpenID4VCI 1.0's published spec text uses that identifier (an earlier SD-JWT VC draft's spelling),
 * while OpenID4VP 1.1's own vendored spec text — and everything this enum emits via {@link #identifier()}
 * — uses the newer {@code dc+sd-jwt}. Both names refer to the same credential format; this lets a
 * consumer (e.g. the sibling oid4vci project's Issuer Metadata, which is spec-literal about emitting
 * {@code vc+sd-jwt}) round-trip through this shared enum without needing its own parallel format type.
 */
public enum CredentialFormat {
    DC_SD_JWT("dc+sd-jwt", "vc+sd-jwt"),
    JWT_VC_JSON("jwt_vc_json"),
    LDP_VC("ldp_vc"),
    MSO_MDOC("mso_mdoc");

    private final String identifier;
    private final Set<String> recognizedIdentifiers;

    CredentialFormat(String identifier, String... aliases) {
        this.identifier = identifier;
        Set<String> recognized = new LinkedHashSet<>();
        recognized.add(identifier);
        recognized.addAll(java.util.Arrays.asList(aliases));
        this.recognizedIdentifiers = Set.copyOf(recognized);
    }

    @JsonValue
    public String identifier() {
        return identifier;
    }

    @JsonCreator
    public static CredentialFormat fromIdentifier(String identifier) {
        for (CredentialFormat format : values()) {
            if (format.recognizedIdentifiers.contains(identifier)) {
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
