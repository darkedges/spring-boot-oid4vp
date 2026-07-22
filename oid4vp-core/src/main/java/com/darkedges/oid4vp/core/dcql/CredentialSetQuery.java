package com.darkedges.oid4vp.core.dcql;

import java.util.List;

/**
 * A Credential Set Query object: one entry in a DCQL query's {@code credential_sets} array.
 *
 * @param options  REQUIRED non-empty array; each element is a non-empty array of Credential Query
 *                 {@code id}s representing one alternative satisfying the use case.
 * @param required OPTIONAL, default {@code true}.
 */
public record CredentialSetQuery(List<List<String>> options, boolean required) {

    public CredentialSetQuery {
        if (options == null || options.isEmpty()) {
            throw new IllegalArgumentException("options must be a non-empty array");
        }
        options = options.stream().map(option -> {
            if (option == null || option.isEmpty()) {
                throw new IllegalArgumentException("each options entry must be a non-empty array of credential ids");
            }
            return List.copyOf(option);
        }).toList();
    }

    public static CredentialSetQuery required(List<List<String>> options) {
        return new CredentialSetQuery(options, true);
    }

    public static CredentialSetQuery optional(List<List<String>> options) {
        return new CredentialSetQuery(options, false);
    }
}
