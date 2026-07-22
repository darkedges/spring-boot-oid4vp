package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Loads the deterministic EC keys and timestamps from
 * {@code docs/1.1/examples/sd_jwt_vcld/settings.yml}, shared by the KB-JWT and end-to-end SD-JWT VC
 * tests so the same source-of-truth fixture drives all of them (rather than hand-transcribed constants).
 */
final class SdJwtVcldFixture {

    private SdJwtVcldFixture() {}

    private static Map<String, Object> settings() {
        return FixtureLoader.readYaml("examples/sd_jwt_vcld/settings.yml");
    }

    @SuppressWarnings("unchecked")
    static ECKey issuerKey() {
        Map<String, Object> settings = settings();
        Map<String, Object> keySettings = (Map<String, Object>) settings.get("key_settings");
        List<Map<String, Object>> issuerKeys = (List<Map<String, Object>>) keySettings.get("issuer_keys");
        return toEcKey(issuerKeys.get(0));
    }

    @SuppressWarnings("unchecked")
    static ECKey holderKey() {
        Map<String, Object> settings = settings();
        Map<String, Object> keySettings = (Map<String, Object>) settings.get("key_settings");
        Map<String, Object> holderKey = (Map<String, Object>) keySettings.get("holder_key");
        return toEcKey(holderKey);
    }

    static String verifierIdentifier() {
        return identifiers().get("verifier").toString();
    }

    static String issuerIdentifier() {
        return identifiers().get("issuer").toString();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> identifiers() {
        return (Map<String, Object>) settings().get("identifiers");
    }

    static String keyBindingNonce() {
        return settings().get("key_binding_nonce").toString();
    }

    static Instant iat() {
        return Instant.ofEpochSecond(((Number) settings().get("iat")).longValue());
    }

    static Instant exp() {
        return Instant.ofEpochSecond(((Number) settings().get("exp")).longValue());
    }

    private static ECKey toEcKey(Map<String, Object> key) {
        ECKey.Builder builder = new ECKey.Builder(Curve.P_256,
                new Base64URL(key.get("x").toString()),
                new Base64URL(key.get("y").toString()));
        if (key.containsKey("d")) {
            builder = builder.d(new Base64URL(key.get("d").toString()));
        }
        return builder.build();
    }
}
