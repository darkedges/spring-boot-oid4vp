package com.darkedges.oid4vp.core.dcql;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;

/** Serializes a {@link DcqlQuery} back to its JSON representation, the inverse of {@link DcqlQueryReader}. */
public final class DcqlQueryWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private DcqlQueryWriter() {}

    public static ObjectNode write(DcqlQuery query) {
        ObjectNode root = NODES.objectNode();
        ArrayNode credentials = root.putArray("credentials");
        query.credentials().forEach(c -> credentials.add(writeCredentialQuery(c)));
        query.credentialSets().ifPresent(sets -> {
            ArrayNode array = root.putArray("credential_sets");
            sets.forEach(s -> array.add(writeCredentialSetQuery(s)));
        });
        return root;
    }

    private static ObjectNode writeCredentialQuery(CredentialQuery credential) {
        ObjectNode node = NODES.objectNode();
        node.put("id", credential.id());
        node.put("format", credential.format().identifier());
        if (credential.multiple()) {
            node.put("multiple", true);
        }
        node.set("meta", writeMeta(credential.meta()));
        if (!credential.trustedAuthorities().isEmpty()) {
            ArrayNode ta = node.putArray("trusted_authorities");
            credential.trustedAuthorities().forEach(t -> {
                ObjectNode taNode = NODES.objectNode();
                taNode.put("type", t.type().value());
                taNode.set("values", writeStringArray(t.values()));
                ta.add(taNode);
            });
        }
        if (!credential.requireCryptographicHolderBinding()) {
            node.put("require_cryptographic_holder_binding", false);
        }
        credential.claims().ifPresent(claims -> {
            ArrayNode array = node.putArray("claims");
            claims.forEach(c -> array.add(writeClaimsQuery(c)));
        });
        credential.claimSets().ifPresent(claimSets -> {
            ArrayNode array = node.putArray("claim_sets");
            claimSets.forEach(option -> array.add(writeStringArray(option)));
        });
        return node;
    }

    private static ObjectNode writeMeta(CredentialQueryMeta meta) {
        ObjectNode node = NODES.objectNode();
        switch (meta) {
            case SdJwtVcMeta m -> node.set("vct_values", writeStringArray(m.vctValues()));
            case JwtVcMeta m -> node.set("type_values", writeStringArrayArray(m.typeValues()));
            case LdpVcMeta m -> node.set("type_values", writeStringArrayArray(m.typeValues()));
            case MsoMdocMeta m -> node.put("doctype_value", m.doctypeValue());
            case CredentialQueryMeta.Empty ignored -> {
                // no fields
            }
        }
        return node;
    }

    private static ObjectNode writeClaimsQuery(ClaimsQuery claim) {
        ObjectNode node = NODES.objectNode();
        claim.id().ifPresent(id -> node.put("id", id));
        node.set("path", claim.path().toJson());
        claim.values().ifPresent(values -> {
            ArrayNode array = node.putArray("values");
            values.forEach(v -> writeClaimsQueryValue(array, v));
        });
        return node;
    }

    private static void writeClaimsQueryValue(ArrayNode array, ClaimsQueryValue value) {
        switch (value) {
            case ClaimsQueryValue.StringValue(String v) -> array.add(v);
            case ClaimsQueryValue.IntegerValue(long v) -> array.add(v);
            case ClaimsQueryValue.BooleanValue(boolean v) -> array.add(v);
        }
    }

    private static ObjectNode writeCredentialSetQuery(CredentialSetQuery set) {
        ObjectNode node = NODES.objectNode();
        ArrayNode options = node.putArray("options");
        set.options().forEach(option -> options.add(writeStringArray(option)));
        if (!set.required()) {
            node.put("required", false);
        }
        return node;
    }

    private static ArrayNode writeStringArray(List<String> values) {
        ArrayNode array = NODES.arrayNode(values.size());
        values.forEach(array::add);
        return array;
    }

    private static ArrayNode writeStringArrayArray(List<List<String>> values) {
        ArrayNode array = NODES.arrayNode(values.size());
        values.forEach(v -> array.add(writeStringArray(v)));
        return array;
    }
}
