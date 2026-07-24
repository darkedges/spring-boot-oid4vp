package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.UnicodeString;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.List;

/** Small helpers around {@code co.nstant.in:cbor}'s low-level API — this module deliberately hand-rolls
 * just enough of the ISO 18013-5 CDDL to read/verify a {@code DeviceResponse}, not a general mdoc-authoring
 * library, so these stay thin rather than growing into a second abstraction layer over the CBOR model. */
final class CborUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CborUtil() {}

    static DataItem decodeSingle(byte[] bytes) {
        List<DataItem> items;
        try {
            items = CborDecoder.decode(bytes);
        } catch (CborException e) {
            throw new MdocVerificationException("failed to decode CBOR", e);
        }
        if (items.size() != 1) {
            throw new MdocVerificationException("expected exactly one top-level CBOR data item, found " + items.size());
        }
        return items.get(0);
    }

    static byte[] encode(DataItem item) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            new CborEncoder(out).encode(item);
        } catch (CborException e) {
            throw new MdocVerificationException("failed to encode CBOR", e);
        }
        return out.toByteArray();
    }

    static Map requireMap(DataItem item) {
        if (!(item instanceof Map map)) {
            throw new MdocVerificationException("expected a CBOR map, was: " + describe(item));
        }
        return map;
    }

    static Array requireArray(DataItem item) {
        if (!(item instanceof Array array)) {
            throw new MdocVerificationException("expected a CBOR array, was: " + describe(item));
        }
        return array;
    }

    static byte[] requireBytes(DataItem item) {
        if (!(item instanceof ByteString byteString)) {
            throw new MdocVerificationException("expected a CBOR byte string, was: " + describe(item));
        }
        return byteString.getBytes();
    }

    static String requireText(DataItem item) {
        if (!(item instanceof UnicodeString unicodeString)) {
            throw new MdocVerificationException("expected a CBOR text string, was: " + describe(item));
        }
        return unicodeString.getString();
    }

    static long requireLong(DataItem item) {
        if (!(item instanceof Number number)) {
            throw new MdocVerificationException("expected a CBOR integer, was: " + describe(item));
        }
        return number.getValue().longValueExact();
    }

    /** {@code map.get(key)}, requiring the key be present. */
    static DataItem get(Map map, String key) {
        DataItem value = map.get(new UnicodeString(key));
        if (value == null) {
            throw new MdocVerificationException("missing required CBOR map key: \"" + key + "\"");
        }
        return value;
    }

    /** {@code map.get(key)}, or {@code null} if absent. */
    static DataItem getOrNull(Map map, String key) {
        return map.get(new UnicodeString(key));
    }

    /** Unwraps an {@code IssuerSignedItemBytes}/{@code MobileSecurityObjectBytes}-style
     * {@code #6.24(bstr .cbor X)}: a byte string tagged 24, whose content re-decodes to the actual item. */
    static DataItem unwrapEncodedCbor(DataItem item) {
        if (!item.hasTag() || item.getTag().getValue() != 24 || !(item instanceof ByteString byteString)) {
            throw new MdocVerificationException(
                    "expected a #6.24(bstr .cbor ...) encoded-CBOR wrapper, was: " + describe(item));
        }
        return decodeSingle(byteString.getBytes());
    }

    /** Converts a CBOR {@code elementValue} into an equivalent {@link JsonNode} tree — text/number/
     * boolean/null map onto their obvious Jackson equivalents; byte strings become base64url text
     * (there's no binary JSON type); arrays/maps recurse. Map keys are required to be text strings, the
     * only kind mdoc's {@code IssuerSignedItem.elementValue} ever nests in this project's usage. */
    static JsonNode toJson(DataItem item) {
        if (item instanceof UnicodeString unicodeString) {
            return MAPPER.getNodeFactory().textNode(unicodeString.getString());
        }
        if (item instanceof Number number) {
            return MAPPER.getNodeFactory().numberNode(number.getValue());
        }
        if (item instanceof SimpleValue simpleValue) {
            return switch (simpleValue.getSimpleValueType()) {
                case TRUE -> MAPPER.getNodeFactory().booleanNode(true);
                case FALSE -> MAPPER.getNodeFactory().booleanNode(false);
                case NULL, UNDEFINED -> MAPPER.getNodeFactory().nullNode();
                default -> throw new MdocVerificationException("unsupported CBOR simple value: " + simpleValue);
            };
        }
        if (item instanceof ByteString byteString) {
            return MAPPER.getNodeFactory().textNode(Base64.getUrlEncoder().withoutPadding().encodeToString(byteString.getBytes()));
        }
        if (item instanceof Array array) {
            ArrayNode node = MAPPER.createArrayNode();
            array.getDataItems().forEach(child -> node.add(toJson(child)));
            return node;
        }
        if (item instanceof Map map) {
            ObjectNode node = MAPPER.createObjectNode();
            for (DataItem key : map.getKeys()) {
                node.set(requireText(key), toJson(map.get(key)));
            }
            return node;
        }
        throw new MdocVerificationException("unsupported CBOR value in elementValue: " + item);
    }

    private static String describe(DataItem item) {
        return item == null ? "null" : item.getMajorType().toString();
    }
}
