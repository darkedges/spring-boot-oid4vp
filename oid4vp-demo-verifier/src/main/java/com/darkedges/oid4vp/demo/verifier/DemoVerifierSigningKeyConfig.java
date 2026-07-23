package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Loads a static, self-signed EC key + certificate ({@code demo-verifier-signing-key.p12}, checked into
 * resources, SANs {@code localhost}/{@code verifier}/{@code verify.irving.au}) used to sign the
 * Authorization Request Object hosted at {@code /oid4vp/request/{registrationId}} — required for the
 * {@code x509_san_dns} Client Identifier Prefix (see {@code application.yml}'s {@code client-id}), since
 * unlike {@code redirect_uri:}, that scheme requires signed requests, verified by the Wallet directly
 * against the leaf certificate carried in the request's {@code x5c} JWS header.
 *
 * <p>Not a pattern to copy for a real Verifier — a real deployment would use a certificate issued by a
 * CA the relying Wallets actually trust, not a self-signed one baked into the jar.
 *
 * <p>Built via plain {@link KeyStore} rather than Nimbus's {@code ECKey.load(KeyStore, ...)}: that
 * convenience method reaches for BouncyCastle internally, and this project has no BouncyCastle dependency
 * (JDK 21's native EC support covers everything else) — not worth adding one just for this.
 */
@Configuration
public class DemoVerifierSigningKeyConfig {

    private static final String KEYSTORE_RESOURCE = "/demo-verifier-signing-key.p12";
    private static final String ALIAS = "demo-verifier-signing";
    private static final char[] PASSWORD = "changeit".toCharArray();

    @Bean
    public ECKey demoVerifierSigningKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = DemoVerifierSigningKeyConfig.class.getResourceAsStream(KEYSTORE_RESOURCE)) {
            keyStore.load(in, PASSWORD);
        }

        ECPrivateKey privateKey = (ECPrivateKey) keyStore.getKey(ALIAS, PASSWORD);
        Certificate[] chain = keyStore.getCertificateChain(ALIAS);
        ECPublicKey publicKey = (ECPublicKey) chain[0].getPublicKey();
        List<Base64> x5c = Arrays.stream(chain)
                .map(cert -> {
                    try {
                        return Base64.encode(cert.getEncoded());
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                })
                .toList();

        return new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .keyID(ALIAS)
                .x509CertChain(x5c)
                .build();
    }

    @Bean
    public RequestObjectSigningKeyResolver requestObjectSigningKeyResolver(ECKey demoVerifierSigningKey) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode signingJwk = mapper.readTree(demoVerifierSigningKey.toJSONString());
        return registrationId -> Optional.of(signingJwk);
    }
}
