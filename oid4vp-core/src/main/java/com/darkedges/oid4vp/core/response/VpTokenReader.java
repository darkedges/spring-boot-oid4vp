package com.darkedges.oid4vp.core.response;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Parses a {@link VpToken} from its JSON object representation (the {@code vp_token} form/JSON field). */
public final class VpTokenReader {

    private VpTokenReader() {}

    public static VpToken read(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("vp_token must be a JSON object");
        }
        Map<String, List<PresentationEntry>> presentations = new LinkedHashMap<>();
        root.fields().forEachRemaining(entry -> {
            JsonNode arrayNode = entry.getValue();
            if (!arrayNode.isArray()) {
                throw new IllegalArgumentException("vp_token entry \"" + entry.getKey() + "\" must be an array");
            }
            List<PresentationEntry> list = new ArrayList<>();
            arrayNode.forEach(element -> list.add(
                    element.isTextual()
                            ? new PresentationEntry.StringPresentation(element.textValue())
                            : new PresentationEntry.ObjectPresentation(element)));
            presentations.put(entry.getKey(), list);
        });
        return new VpToken(presentations);
    }
}
