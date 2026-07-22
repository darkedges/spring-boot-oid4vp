package com.darkedges.oid4vp.core.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * A claims path pointer: a non-empty array of strings, nulls, and non-negative integers identifying one
 * or more claims within a Credential (OpenID4VP 1.1, "Claims Path Pointer").
 *
 * <p>{@link #select(JsonNode)} implements the "Semantics for JSON-based credentials" processing
 * algorithm. The "Semantics for ISO mdoc-based credentials" variant (exactly two string components,
 * namespace + data element identifier) is out of scope for this phase and is not implemented here.
 */
public record ClaimsPathPointer(List<PathComponent> components) {

    public ClaimsPathPointer {
        if (components == null || components.isEmpty()) {
            throw new IllegalArgumentException("claims path pointer must be a non-empty array");
        }
        components = List.copyOf(components);
    }

    public static ClaimsPathPointer of(Object... rawComponents) {
        List<PathComponent> parsed = new ArrayList<>(rawComponents.length);
        for (Object raw : rawComponents) {
            parsed.add(toPathComponent(raw));
        }
        return new ClaimsPathPointer(parsed);
    }

    public static ClaimsPathPointer parse(JsonNode arrayNode) {
        if (arrayNode == null || !arrayNode.isArray() || arrayNode.isEmpty()) {
            throw new IllegalArgumentException("claims path pointer must be a non-empty JSON array");
        }
        List<PathComponent> parsed = new ArrayList<>(arrayNode.size());
        for (JsonNode element : arrayNode) {
            parsed.add(toPathComponent(element));
        }
        return new ClaimsPathPointer(parsed);
    }

    private static PathComponent toPathComponent(JsonNode element) {
        if (element == null || element.isNull()) {
            return PathComponent.AllElements.INSTANCE;
        }
        if (element.isTextual()) {
            return new PathComponent.Key(element.textValue());
        }
        if (element.isIntegralNumber() && element.intValue() >= 0) {
            return new PathComponent.Index(element.intValue());
        }
        throw new IllegalArgumentException(
                "claims path pointer component must be a string, null, or non-negative integer, was: " + element);
    }

    private static PathComponent toPathComponent(Object raw) {
        if (raw == null) {
            return PathComponent.AllElements.INSTANCE;
        }
        if (raw instanceof String s) {
            return new PathComponent.Key(s);
        }
        if (raw instanceof Integer i && i >= 0) {
            return new PathComponent.Index(i);
        }
        throw new IllegalArgumentException(
                "claims path pointer component must be a String, null, or non-negative Integer, was: " + raw);
    }

    /**
     * Applies the "Semantics for JSON-based credentials" processing algorithm and returns the set of
     * selected JSON elements.
     *
     * @throws ClaimsPathPointerException if processing aborts (a type mismatch at some step, or an
     *                                     empty final selection)
     */
    public List<JsonNode> select(JsonNode credentialRoot) {
        List<JsonNode> current = List.of(credentialRoot);
        for (PathComponent component : components) {
            current = switch (component) {
                case PathComponent.Key key -> selectKey(current, key.name());
                case PathComponent.AllElements ignored -> selectAllElements(current);
                case PathComponent.Index index -> selectIndex(current, index.value());
            };
        }
        if (current.isEmpty()) {
            throw new ClaimsPathPointerException(
                    "claims path pointer selection is empty after processing: " + components);
        }
        return current;
    }

    private static List<JsonNode> selectKey(List<JsonNode> current, String name) {
        List<JsonNode> next = new ArrayList<>();
        for (JsonNode node : current) {
            if (!node.isObject()) {
                throw new ClaimsPathPointerException(
                        "claims path pointer component \"" + name + "\" expects an object, found: " + node.getNodeType());
            }
            if (node.has(name)) {
                next.add(node.get(name));
            }
        }
        return next;
    }

    private static List<JsonNode> selectAllElements(List<JsonNode> current) {
        List<JsonNode> next = new ArrayList<>();
        for (JsonNode node : current) {
            if (!node.isArray()) {
                throw new ClaimsPathPointerException(
                        "claims path pointer component null expects an array, found: " + node.getNodeType());
            }
            node.forEach(next::add);
        }
        return next;
    }

    private static List<JsonNode> selectIndex(List<JsonNode> current, int index) {
        List<JsonNode> next = new ArrayList<>();
        for (JsonNode node : current) {
            if (!node.isArray()) {
                throw new ClaimsPathPointerException(
                        "claims path pointer component " + index + " expects an array, found: " + node.getNodeType());
            }
            if (index < node.size()) {
                next.add(node.get(index));
            }
        }
        return next;
    }

    /** True iff this pointer has the mdoc shape (exactly two string components: namespace, element id). */
    public boolean isMdocShape() {
        return components.size() == 2
                && components.get(0) instanceof PathComponent.Key
                && components.get(1) instanceof PathComponent.Key;
    }

    public ArrayNode toJson() {
        ArrayNode array = JsonNodeFactory.instance.arrayNode(components.size());
        for (PathComponent component : components) {
            switch (component) {
                case PathComponent.Key key -> array.add(key.name());
                case PathComponent.AllElements ignored -> array.addNull();
                case PathComponent.Index index -> array.add(index.value());
            }
        }
        return array;
    }
}
