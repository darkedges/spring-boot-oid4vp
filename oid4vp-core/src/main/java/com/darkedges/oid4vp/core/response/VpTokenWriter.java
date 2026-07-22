package com.darkedges.oid4vp.core.response;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Serializes a {@link VpToken} back to its JSON object representation, the inverse of {@link VpTokenReader}. */
public final class VpTokenWriter {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private VpTokenWriter() {}

    public static ObjectNode write(VpToken vpToken) {
        ObjectNode root = NODES.objectNode();
        vpToken.presentations().forEach((id, entries) -> {
            ArrayNode array = root.putArray(id);
            for (PresentationEntry entry : entries) {
                switch (entry) {
                    case PresentationEntry.StringPresentation(String value) -> array.add(value);
                    case PresentationEntry.ObjectPresentation(JsonNode value) -> array.add(value);
                }
            }
        });
        return root;
    }
}
