package com.darkedges.oid4vp.core.dcql;

import java.util.List;
import java.util.Optional;

/**
 * A Credential Query object: one entry in a DCQL query's {@code credentials} array.
 *
 * @param id                                REQUIRED, unique within the query, matches {@code [A-Za-z0-9_-]+}.
 * @param format                            REQUIRED Credential Format Identifier.
 * @param multiple                          OPTIONAL, default {@code false}.
 * @param meta                              REQUIRED (may be an "empty" constraint, per format).
 * @param trustedAuthorities                OPTIONAL non-empty array if present.
 * @param requireCryptographicHolderBinding OPTIONAL, default {@code true}.
 * @param claims                            OPTIONAL non-empty array if present.
 * @param claimSets                         OPTIONAL non-empty array-of-arrays of {@code claims[].id} references.
 */
public record CredentialQuery(
        String id,
        CredentialFormat format,
        boolean multiple,
        CredentialQueryMeta meta,
        List<TrustedAuthoritiesQuery> trustedAuthorities,
        boolean requireCryptographicHolderBinding,
        Optional<List<ClaimsQuery>> claims,
        Optional<List<List<String>>> claimSets) {

    private static final String ID_PATTERN = "[A-Za-z0-9_-]+";

    public CredentialQuery {
        if (id == null || !id.matches(ID_PATTERN)) {
            throw new IllegalArgumentException("credential query id must match " + ID_PATTERN + ", was: " + id);
        }
        if (format == null) {
            throw new IllegalArgumentException("format is required");
        }
        if (meta == null) {
            throw new IllegalArgumentException("meta is required (use CredentialQueryMeta.Empty.INSTANCE if empty)");
        }
        trustedAuthorities = trustedAuthorities == null ? List.of() : List.copyOf(trustedAuthorities);
        claims = claims == null ? Optional.empty() : claims.map(List::copyOf);
        claimSets = claimSets == null ? Optional.empty() : claimSets.map(l -> l.stream().map(List::copyOf).toList());
    }

    public static CredentialQuery.Builder builder(String id, CredentialFormat format) {
        return new Builder(id, format);
    }

    /** Convenience mutable builder; the record itself remains fully immutable. */
    public static final class Builder {
        private final String id;
        private final CredentialFormat format;
        private boolean multiple = false;
        private CredentialQueryMeta meta = CredentialQueryMeta.Empty.INSTANCE;
        private List<TrustedAuthoritiesQuery> trustedAuthorities = List.of();
        private boolean requireCryptographicHolderBinding = true;
        private Optional<List<ClaimsQuery>> claims = Optional.empty();
        private Optional<List<List<String>>> claimSets = Optional.empty();

        private Builder(String id, CredentialFormat format) {
            this.id = id;
            this.format = format;
        }

        public Builder multiple(boolean multiple) {
            this.multiple = multiple;
            return this;
        }

        public Builder meta(CredentialQueryMeta meta) {
            this.meta = meta;
            return this;
        }

        public Builder trustedAuthorities(List<TrustedAuthoritiesQuery> trustedAuthorities) {
            this.trustedAuthorities = trustedAuthorities;
            return this;
        }

        public Builder requireCryptographicHolderBinding(boolean value) {
            this.requireCryptographicHolderBinding = value;
            return this;
        }

        public Builder claims(List<ClaimsQuery> claims) {
            this.claims = Optional.ofNullable(claims);
            return this;
        }

        public Builder claimSets(List<List<String>> claimSets) {
            this.claimSets = Optional.ofNullable(claimSets);
            return this;
        }

        public CredentialQuery build() {
            return new CredentialQuery(
                    id, format, multiple, meta, trustedAuthorities, requireCryptographicHolderBinding, claims, claimSets);
        }
    }
}
