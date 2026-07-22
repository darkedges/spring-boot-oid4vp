package com.darkedges.oid4vp.core.response;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * One element of a {@link VpToken} entry's array: either a string-serialized presentation (used by
 * {@code dc+sd-jwt}, {@code jwt_vc_json}, and mdoc's base64url {@code DeviceResponse}) or a JSON object
 * presentation (used by {@code ldp_vc}).
 */
public sealed interface PresentationEntry {

    record StringPresentation(String value) implements PresentationEntry {
        public StringPresentation {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
        }
    }

    record ObjectPresentation(JsonNode value) implements PresentationEntry {
        public ObjectPresentation {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
        }
    }
}
