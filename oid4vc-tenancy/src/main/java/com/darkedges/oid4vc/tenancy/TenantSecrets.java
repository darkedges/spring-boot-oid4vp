package com.darkedges.oid4vc.tenancy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.Iterator;
import java.util.Map;

/**
 * A tenant's write-only settings: the values under {@code settings.secrets} (a proofing callback secret, a trust key). They are
 * never shown again, only whether each is set.
 *
 * <p>An update's {@code secrets}: a string sets that secret, {@code null} removes it, and an omitted name keeps it.
 */
public final class TenantSecrets {

    public static final String FIELD = "secrets";

    private TenantSecrets() {}

    /** The settings as an administrator may see them: each secret replaced by {@code {"set": true}}. */
    public static ObjectNode redact(ObjectNode settings) {
        ObjectNode copy = settings.deepCopy();
        JsonNode secrets = copy.get(FIELD);
        if (secrets instanceof ObjectNode secretObject) {
            ObjectNode shown = copy.putObject(FIELD);
            secretObject.fieldNames().forEachRemaining(name -> shown.putObject(name).put("set", true));
        }
        return copy;
    }

    /** Applies an update's settings over the stored ones, following the rules for secrets. */
    public static ObjectNode merge(ObjectNode stored, ObjectNode update) {
        ObjectNode result = update.deepCopy();
        ObjectNode kept = stored.get(FIELD) instanceof ObjectNode s ? s.deepCopy() : result.objectNode();
        JsonNode requested = update.get(FIELD);
        if (requested instanceof ObjectNode changes) {
            Iterator<Map.Entry<String, JsonNode>> it = changes.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> change = it.next();
                if (change.getValue().isNull()) kept.remove(change.getKey());
                else if (change.getValue().isTextual()) kept.put(change.getKey(), change.getValue().asText());
                else if (!change.getValue().isObject()) {
                    // {"set": true}, as returned by redact, means "unchanged"; anything else is a mistake.
                    throw new IllegalArgumentException("a secret is a string, or null to remove it: " + change.getKey());
                }
            }
        } else if (requested != null && !requested.isNull()) {
            throw new IllegalArgumentException("\"secrets\" must be an object");
        }
        if (kept.isEmpty()) result.remove(FIELD);
        else result.set(FIELD, kept);
        return result;
    }

    public static String secret(Tenant tenant, String name) {
        JsonNode value = tenant.settings().path(FIELD).path(name);
        return value.isTextual() ? value.asText() : null;
    }
}
