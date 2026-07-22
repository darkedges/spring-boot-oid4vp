package com.darkedges.oid4vp.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * An SD-JWT Disclosure: {@code [salt, claimName, claimValue]} for an object property, or
 * {@code [salt, claimValue]} for an array element, base64url-encoded as a single string.
 */
public record Disclosure(String salt, Optional<String> claimName, JsonNode claimValue, String rawBase64Url) {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public Disclosure {
        if (salt == null || salt.isBlank()) {
            throw new IllegalArgumentException("salt is required");
        }
        if (claimValue == null) {
            throw new IllegalArgumentException("claimValue is required");
        }
        claimName = claimName == null ? Optional.empty() : claimName;
        if (rawBase64Url == null || rawBase64Url.isBlank()) {
            throw new IllegalArgumentException("rawBase64Url is required");
        }
    }

    public static Disclosure parse(String base64Url) {
        JsonNode array;
        try {
            array = MAPPER.readTree(Base64URL.from(base64Url).decode());
        } catch (Exception e) {
            throw new IllegalArgumentException("disclosure is not valid base64url-encoded JSON: " + base64Url, e);
        }
        if (!array.isArray()) {
            throw new IllegalArgumentException("disclosure must decode to a JSON array: " + base64Url);
        }
        return switch (array.size()) {
            case 2 -> new Disclosure(array.get(0).asText(), Optional.empty(), array.get(1), base64Url);
            case 3 -> new Disclosure(array.get(0).asText(), Optional.of(array.get(1).asText()), array.get(2), base64Url);
            default -> throw new IllegalArgumentException(
                    "disclosure array must have 2 (array element) or 3 (object property) elements: " + base64Url);
        };
    }

    public static Disclosure createObjectProperty(String salt, String claimName, JsonNode claimValue) {
        ArrayNode array = JsonNodeFactory.instance.arrayNode(3).add(salt).add(claimName).add(claimValue);
        String raw = Base64URL.encode(array.toString().getBytes(StandardCharsets.UTF_8)).toString();
        return new Disclosure(salt, Optional.of(claimName), claimValue, raw);
    }

    public static Disclosure createArrayElement(String salt, JsonNode claimValue) {
        ArrayNode array = JsonNodeFactory.instance.arrayNode(2).add(salt).add(claimValue);
        String raw = Base64URL.encode(array.toString().getBytes(StandardCharsets.UTF_8)).toString();
        return new Disclosure(salt, Optional.empty(), claimValue, raw);
    }

    /** The digest that must appear in an {@code _sd} array for this disclosure to be considered
     * disclosed: {@code base64url(hash(ASCII(rawBase64Url)))}. */
    public String digest(String hashAlg) {
        byte[] hash = HashAlgorithms.newDigest(hashAlg).digest(rawBase64Url.getBytes(StandardCharsets.US_ASCII));
        return Base64URL.encode(hash).toString();
    }

    public String digest() {
        return digest(HashAlgorithms.DEFAULT);
    }
}
