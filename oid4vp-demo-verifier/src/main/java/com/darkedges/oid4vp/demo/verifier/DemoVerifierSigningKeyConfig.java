package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The EC key and certificate that sign the Authorization Request Object hosted at {@code /oid4vp/request/{registrationId}}, which the
 * {@code x509_hash} Client Identifier Prefix requires: a Wallet verifies the signature against the leaf certificate in the request's
 * {@code x5c} header.
 *
 * <ul>
 *   <li><b>For local development,</b> {@code demo-verifier-signing-key.p12} from this module's resources: a leaf (SANs
 *       {@code localhost}/{@code verifier}) issued by a demo CA. <b>Its private key is published with this source</b>, so a signature
 *       by it proves nothing about who sent a request.</li>
 *   <li><b>Deployed,</b> your own: {@code demo.signing.keystore} (a PKCS#12 file, entry {@code demo-verifier-signing}, kept outside
 *       the source tree) and {@code demo.signing.keystore-password}. With {@code demo.signing.require-external-key=true}, as the
 *       {@code cloudflare} profile sets, the application refuses to start without one, or with the published one.</li>
 * </ul>
 *
 * <p>The {@code x5c} header carries only the leaf, not the CA: HAIP's x5c validation rejects a chain that includes the trust anchor,
 * which a Wallet is expected to know already. With a key of your own, {@link DemoVerifierIdentity} makes the registrations'
 * {@code x509_hash} client ids match it.
 *
 * <p>Built via plain {@link KeyStore} rather than Nimbus's {@code ECKey.load(KeyStore, ...)}: that convenience method reaches for
 * BouncyCastle internally, and this project has no BouncyCastle dependency.
 */
@Configuration
public class DemoVerifierSigningKeyConfig {

    private static final String PUBLISHED_KEYSTORE = "/demo-verifier-signing-key.p12";
    private static final String ALIAS = "demo-verifier-signing";
    private static final char[] PUBLISHED_PASSWORD = "changeit".toCharArray();

    @Bean
    public ECKey demoVerifierSigningKey(Environment environment) throws Exception {
        String file = environment.getProperty("demo.signing.keystore", "");
        boolean required = environment.getProperty("demo.signing.require-external-key", Boolean.class, false);
        if (file.isBlank()) {
            if (required) {
                throw new IllegalStateException("This deployment needs its own request signing key: set demo.signing.keystore "
                        + "(DEMO_SIGNING_KEYSTORE) and demo.signing.keystore-password. The key shipped with the source is public.");
            }
            return published();
        }
        ECKey own;
        try (InputStream in = Files.newInputStream(Path.of(file))) {
            own = load(in, environment.getProperty("demo.signing.keystore-password", "").toCharArray());
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read the request signing keystore " + file + ": " + e.getMessage(), e);
        }
        if (required && Arrays.equals(own.toECPublicKey().getEncoded(), published().toECPublicKey().getEncoded())) {
            throw new IllegalStateException("demo.signing.keystore holds the key shipped with the source, which is public: "
                    + "generate a new one");
        }
        return own;
    }

    static ECKey published() throws Exception {
        try (InputStream in = DemoVerifierSigningKeyConfig.class.getResourceAsStream(PUBLISHED_KEYSTORE)) {
            return load(in, PUBLISHED_PASSWORD);
        }
    }

    private static ECKey load(InputStream in, char[] password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(in, password);
        ECPrivateKey privateKey = (ECPrivateKey) keyStore.getKey(ALIAS, password);
        Certificate[] chain = keyStore.getCertificateChain(ALIAS);
        if (privateKey == null || chain == null) {
            throw new IllegalStateException("the keystore has no private key entry \"" + ALIAS + "\"");
        }
        // Leaf only, not the full chain (OID4VP 1.0 section 5.9.3, and HAIP's x5c validation).
        Certificate leaf = chain[0];
        ECPublicKey publicKey = (ECPublicKey) leaf.getPublicKey();
        return new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID(ALIAS)
                .x509CertChain(List.of(Base64.encode(leaf.getEncoded())))
                .build();
    }

    @Bean
    public RequestObjectSigningKeyResolver requestObjectSigningKeyResolver(ECKey demoVerifierSigningKey) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode signingJwk = mapper.readTree(demoVerifierSigningKey.toJSONString());
        return registrationId -> Optional.of(signingJwk);
    }
}
