package com.darkedges.oid4vp.core.dcql;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * One element of a Claims Query's {@code values} array: a best-effort claim value to match against.
 * Per OpenID4VP 1.1, this is <em>not</em> a security control and MUST NOT be relied on as one.
 */
public sealed interface ClaimsQueryValue {

    record StringValue(String value) implements ClaimsQueryValue {}

    record IntegerValue(long value) implements ClaimsQueryValue {}

    record BooleanValue(boolean value) implements ClaimsQueryValue {}

    static ClaimsQueryValue of(String value) {
        return new StringValue(value);
    }

    static ClaimsQueryValue of(long value) {
        return new IntegerValue(value);
    }

    static ClaimsQueryValue of(boolean value) {
        return new BooleanValue(value);
    }

    static ClaimsQueryValue parse(JsonNode node) {
        if (node.isTextual()) {
            return new StringValue(node.textValue());
        }
        if (node.isBoolean()) {
            return new BooleanValue(node.booleanValue());
        }
        if (node.isIntegralNumber()) {
            return new IntegerValue(node.longValue());
        }
        throw new IllegalArgumentException("claims query value must be a string, integer, or boolean, was: " + node);
    }

    /** True iff the given (format-converted-to-JSON) claim value matches this query value exactly. */
    default boolean matches(JsonNode claimValue) {
        return switch (this) {
            case StringValue(String value) -> claimValue.isTextual() && claimValue.textValue().equals(value);
            case IntegerValue(long value) -> claimValue.isIntegralNumber() && claimValue.longValue() == value;
            case BooleanValue(boolean value) -> claimValue.isBoolean() && claimValue.booleanValue() == value;
        };
    }
}
