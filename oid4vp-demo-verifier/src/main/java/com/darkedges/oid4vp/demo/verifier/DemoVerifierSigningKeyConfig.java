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
import java.util.List;
import java.util.Optional;

/**
 * Loads a static EC key + certificate ({@code demo-verifier-signing-key.p12}, checked into resources: a
 * leaf cert with SANs {@code localhost}/{@code verifier}/{@code verify.irving.au}, issued by a self-signed
 * demo CA also stored in the same keystore — the leaf itself is <em>not</em> self-signed, since
 * HAIP-conformant Wallets reject a self-signed leaf) used to sign the Authorization Request Object hosted
 * at {@code /oid4vp/request/{registrationId}} — required for the {@code x509_hash} Client Identifier
 * Prefix (see {@code application.yml}'s {@code client-id}), since unlike {@code redirect_uri:}, that
 * scheme requires signed requests, verified by the Wallet directly against the leaf certificate carried in
 * the request's {@code x5c} JWS header. The {@code x5c} header carries only the leaf, not the CA: the demo
 * CA is registered out-of-band as the Wallet/conformance suite's trust anchor, and HAIP's x5c validation
 * rejects a chain that includes the trust anchor certificate itself.
 *
 * <p>Not a pattern to copy for a real Verifier — a real deployment would use a certificate issued by a CA
 * relying Wallets actually trust, not a throwaway demo CA baked into the jar. If this keystore is ever
 * regenerated, every registration's {@code client-id} (the leaf's {@code x509_hash}) must be recomputed
 * to match — see {@code application.yml}'s {@code demo} registration for the exact derivation.
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
        // Leaf only, not the full chain: the demo CA is registered out-of-band as the conformance suite's
        // trust anchor, and HAIP's x5c validation rejects a chain that includes the trust anchor itself
        // (OID4VP-1FINAL-5.9.3 ValidateRequestObjectSignatureAgainstX5cHeader).
        Certificate leaf = keyStore.getCertificateChain(ALIAS)[0];
        ECPublicKey publicKey = (ECPublicKey) leaf.getPublicKey();
        List<Base64> x5c = List.of(Base64.encode(leaf.getEncoded()));

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
