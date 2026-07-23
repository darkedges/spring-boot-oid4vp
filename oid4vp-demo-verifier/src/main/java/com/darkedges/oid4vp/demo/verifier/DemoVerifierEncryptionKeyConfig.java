package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.response.ResponseDecryptionKeyResolver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Optional;

/**
 * A static demo EC (P-256) encryption key, used only by the {@code conformance} relying-party
 * registration (see {@code application-cloudflare.yml}) for {@code direct_post.jwt} (encrypted response
 * mode) — required by some conformance test plans. Generated once (Nimbus's {@code ECKeyGenerator} via
 * jshell), not at startup like the signing key: its <em>public</em> half has to be embedded verbatim in
 * {@code client-metadata}'s static YAML JSON, so unlike a fresh-per-run key, it has to stay fixed across
 * restarts for the two to actually match.
 *
 * <p>Demo-only, not a pattern to copy for a real deployment, which would manage this key material
 * properly rather than checking a private key into source control.
 */
@Configuration
public class DemoVerifierEncryptionKeyConfig {

    // Public half is embedded in application-cloudflare.yml's client-metadata — keep them in sync if this
    // is ever regenerated.
    private static final String PRIVATE_JWK = """
            {"kty":"EC","d":"Zva3XzTqcsliES7adB-_V9RK21YkqhBEKLT5s7HZXUQ","use":"enc","crv":"P-256",
            "kid":"demo-verifier-encryption","x":"xrGuOuYtOsauuXNHkXlsFo93P14Yfu1VNXmpZR9-9JI",
            "y":"b_Xpz-0tRjZfXuwuA-UClHGO2P9t03b0qPeV9yn-cY0","alg":"ECDH-ES"}""";

    @Bean
    public ResponseDecryptionKeyResolver responseDecryptionKeyResolver() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode privateJwk = mapper.readTree(PRIVATE_JWK);
        ObjectNode privateJwks = mapper.createObjectNode();
        privateJwks.putArray("keys").add(privateJwk);
        return registrationId -> Optional.of(privateJwks);
    }
}
