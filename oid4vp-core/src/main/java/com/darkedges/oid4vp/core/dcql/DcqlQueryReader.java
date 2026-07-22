package com.darkedges.oid4vp.core.dcql;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Parses a {@link DcqlQuery} (the {@code dcql_query} request parameter) from its JSON representation. */
public final class DcqlQueryReader {

    private DcqlQueryReader() {}

    public static DcqlQuery read(JsonNode root) {
        List<CredentialQuery> credentials = new ArrayList<>();
        for (JsonNode node : requireArray(root, "credentials")) {
            credentials.add(readCredentialQuery(node));
        }

        Optional<List<CredentialSetQuery>> credentialSets = Optional.empty();
        if (root.hasNonNull("credential_sets")) {
            List<CredentialSetQuery> sets = new ArrayList<>();
            for (JsonNode node : root.get("credential_sets")) {
                sets.add(readCredentialSetQuery(node));
            }
            credentialSets = Optional.of(sets);
        }

        return new DcqlQuery(credentials, credentialSets);
    }

    private static CredentialQuery readCredentialQuery(JsonNode node) {
        String id = node.required("id").asText();
        CredentialFormat format = CredentialFormat.fromIdentifier(node.required("format").asText());
        boolean multiple = node.path("multiple").asBoolean(false);
        CredentialQueryMeta meta = readMeta(format, node.path("meta"));

        List<TrustedAuthoritiesQuery> trustedAuthorities = List.of();
        if (node.hasNonNull("trusted_authorities")) {
            List<TrustedAuthoritiesQuery> list = new ArrayList<>();
            for (JsonNode taNode : node.get("trusted_authorities")) {
                list.add(new TrustedAuthoritiesQuery(
                        TrustedAuthorityType.fromValue(taNode.required("type").asText()),
                        readStringArray(taNode.required("values"))));
            }
            trustedAuthorities = list;
        }

        boolean requireHolderBinding = node.path("require_cryptographic_holder_binding").asBoolean(true);

        Optional<List<ClaimsQuery>> claims = Optional.empty();
        if (node.hasNonNull("claims")) {
            List<ClaimsQuery> list = new ArrayList<>();
            for (JsonNode claimNode : node.get("claims")) {
                list.add(readClaimsQuery(claimNode));
            }
            claims = Optional.of(list);
        }

        Optional<List<List<String>>> claimSets = Optional.empty();
        if (node.hasNonNull("claim_sets")) {
            List<List<String>> list = new ArrayList<>();
            for (JsonNode option : node.get("claim_sets")) {
                list.add(readStringArray(option));
            }
            claimSets = Optional.of(list);
        }

        return new CredentialQuery(
                id, format, multiple, meta, trustedAuthorities, requireHolderBinding, claims, claimSets);
    }

    private static CredentialQueryMeta readMeta(CredentialFormat format, JsonNode metaNode) {
        if (metaNode == null || metaNode.isMissingNode()) {
            throw new IllegalArgumentException("meta is required");
        }
        return switch (format) {
            case DC_SD_JWT -> new SdJwtVcMeta(readStringArray(metaNode.path("vct_values")));
            case JWT_VC_JSON -> new JwtVcMeta(readStringArrayArray(metaNode.path("type_values")));
            case LDP_VC -> new LdpVcMeta(readStringArrayArray(metaNode.path("type_values")));
            case MSO_MDOC -> new MsoMdocMeta(metaNode.path("doctype_value").asText());
        };
    }

    private static ClaimsQuery readClaimsQuery(JsonNode node) {
        Optional<String> id = node.hasNonNull("id") ? Optional.of(node.get("id").asText()) : Optional.empty();
        ClaimsPathPointer path = ClaimsPathPointer.parse(node.required("path"));
        Optional<List<ClaimsQueryValue>> values = Optional.empty();
        if (node.hasNonNull("values")) {
            List<ClaimsQueryValue> list = new ArrayList<>();
            for (JsonNode valueNode : node.get("values")) {
                list.add(ClaimsQueryValue.parse(valueNode));
            }
            values = Optional.of(list);
        }
        return new ClaimsQuery(id, path, values);
    }

    private static CredentialSetQuery readCredentialSetQuery(JsonNode node) {
        List<List<String>> options = new ArrayList<>();
        for (JsonNode option : node.required("options")) {
            options.add(readStringArray(option));
        }
        boolean required = node.path("required").asBoolean(true);
        return new CredentialSetQuery(options, required);
    }

    private static List<String> readStringArray(JsonNode arrayNode) {
        List<String> values = new ArrayList<>();
        if (arrayNode != null && arrayNode.isArray()) {
            arrayNode.forEach(n -> values.add(n.asText()));
        }
        return values;
    }

    private static List<List<String>> readStringArrayArray(JsonNode arrayNode) {
        List<List<String>> values = new ArrayList<>();
        if (arrayNode != null && arrayNode.isArray()) {
            arrayNode.forEach(n -> values.add(readStringArray(n)));
        }
        return values;
    }

    private static JsonNode requireArray(JsonNode root, String field) {
        JsonNode node = root.required(field);
        if (!node.isArray()) {
            throw new IllegalArgumentException(field + " must be an array");
        }
        return node;
    }
}
