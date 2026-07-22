package com.darkedges.oid4vp.testfixtures;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Loads fixtures from the classpath: the spec's own examples (copied from {@code docs/1.1/examples} to
 * {@code examples/**}) and the small set of spec-prose examples transcribed under
 * {@code src/main/resources-spec-transcribed} in this module.
 */
public final class FixtureLoader {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private FixtureLoader() {}

    /** Reads a fixture from {@code docs/1.1/examples/<relativePath>}, e.g. {@code "query_lang/simple.json"}. */
    public static String readExample(String relativePath) {
        return readString("examples/" + relativePath);
    }

    public static JsonNode readExampleJson(String relativePath) {
        return readJson("examples/" + relativePath);
    }

    /**
     * Reads a compact-serialized fixture (e.g. an SD-JWT presentation), stripping all whitespace. The
     * {@code .txt} examples under {@code docs/1.1/examples/sd_jwt_vcld/} are hard-wrapped at 68
     * characters per line for readability; the embedded newlines are not part of the actual content
     * (compact JOSE serializations never legitimately contain whitespace).
     */
    public static String readExampleCompact(String relativePath) {
        return readExample(relativePath).replaceAll("\\s+", "");
    }

    public static String readString(String classpathResource) {
        try (InputStream in = requireStream(classpathResource)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read fixture: " + classpathResource, e);
        }
    }

    public static JsonNode readJson(String classpathResource) {
        try (InputStream in = requireStream(classpathResource)) {
            return MAPPER.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to parse JSON fixture: " + classpathResource, e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> readYaml(String classpathResource) {
        try (InputStream in = requireStream(classpathResource)) {
            return (Map<String, Object>) new Yaml().load(in);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read YAML fixture: " + classpathResource, e);
        }
    }

    private static InputStream requireStream(String classpathResource) {
        InputStream in = FixtureLoader.class.getClassLoader().getResourceAsStream(classpathResource);
        if (in == null) {
            throw new IllegalArgumentException("fixture not found on classpath: " + classpathResource);
        }
        return in;
    }
}
