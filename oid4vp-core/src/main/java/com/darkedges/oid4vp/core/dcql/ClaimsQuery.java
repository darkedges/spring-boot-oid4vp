package com.darkedges.oid4vp.core.dcql;

import java.util.List;
import java.util.Optional;

/**
 * A Claims Query object: one entry in a Credential Query's {@code claims} array.
 *
 * @param id     REQUIRED if the Credential Query has {@code claim_sets}, else OPTIONAL; unique within
 *               the array; matches {@code [A-Za-z0-9_-]+}.
 * @param path   REQUIRED claims path pointer into the Credential.
 * @param values OPTIONAL best-effort value-matching constraint (not a security control).
 */
public record ClaimsQuery(Optional<String> id, ClaimsPathPointer path, Optional<List<ClaimsQueryValue>> values) {

    private static final String ID_PATTERN = "[A-Za-z0-9_-]+";

    public ClaimsQuery {
        if (path == null) {
            throw new IllegalArgumentException("path is required");
        }
        id = id == null ? Optional.empty() : id;
        values = values == null ? Optional.empty() : values.map(List::copyOf);
        id.ifPresent(value -> {
            if (!value.matches(ID_PATTERN)) {
                throw new IllegalArgumentException("claims query id must match " + ID_PATTERN + ", was: " + value);
            }
        });
    }

    public static ClaimsQuery of(String id, ClaimsPathPointer path) {
        return new ClaimsQuery(Optional.ofNullable(id), path, Optional.empty());
    }
}
