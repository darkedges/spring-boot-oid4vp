package com.darkedges.oid4vp.demo.wallet;

import com.darkedges.oid4vp.mdoc.MdocHeldCredential;
import com.darkedges.oid4vp.mdoc.MdocIssuer;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Self-issues one {@code mso_mdoc} credential (docType {@code org.iso.18013.5.1.mDL}) at startup, so the
 * demo has an mDL to present alongside its SD-JWT VC one. Mirrors {@link DemoCredentialConfig}'s
 * self-issuance pattern; not a stand-in for real mDL issuance (ISO 18013-5 issuance is out of scope here,
 * same as OpenID4VCI is for the SD-JWT VC credential).
 *
 * <p>Unlike {@code demo-verifier-signing-key.p12}'s leaf (which HAIP-conformant Wallets must see issued
 * by a separate CA, not self-signed), this issuer cert can be self-signed: the demo Verifier's
 * {@code IssuerKeyResolver} extracts the mdoc issuer's key straight from {@code IssuerAuth}'s
 * {@code x5chain} leaf with no chain-of-trust validation (see its Javadoc) — a throwaway self-signed cert,
 * generated once via {@code keytool -genkeypair}, is enough.
 */
@Configuration
public class DemoMdocCredentialConfig {

    private static final Logger log = LoggerFactory.getLogger(DemoMdocCredentialConfig.class);

    private static final String KEYSTORE_RESOURCE = "/demo-wallet-mdoc-issuer-key.p12";
    private static final String ALIAS = "demo-wallet-mdoc-issuer";
    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String DOC_TYPE = "org.iso.18013.5.1.mDL";
    private static final String NAMESPACE = "org.iso.18013.5.1";

    @Bean
    public KeyPair demoMdocDeviceKeyPair() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256).keyID("demo-mdoc-device-1").generate().toKeyPair();
    }

    @Bean
    public MdocHeldCredential demoMdocCredential(KeyPair demoMdocDeviceKeyPair) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = DemoMdocCredentialConfig.class.getResourceAsStream(KEYSTORE_RESOURCE)) {
            keyStore.load(in, PASSWORD);
        }
        ECPrivateKey issuerPrivateKey = (ECPrivateKey) keyStore.getKey(ALIAS, PASSWORD);
        Certificate leaf = keyStore.getCertificateChain(ALIAS)[0];
        List<String> x5chain = List.of(Base64.getEncoder().encodeToString(leaf.getEncoded()));

        Instant now = Instant.now();
        byte[] issuerSigned = MdocIssuer.issueIssuerSigned(
                issuerPrivateKey, x5chain, (ECPublicKey) demoMdocDeviceKeyPair.getPublic(), DOC_TYPE,
                Map.of(NAMESPACE, Map.of("given_name", "Jane", "family_name", "Demo")),
                now, now.plusSeconds(365L * 24 * 3600));

        log.info("Self-issued demo mdoc credential: docType={}, disclosable claims=[given_name, family_name]", DOC_TYPE);
        return MdocHeldCredential.parse(issuerSigned);
    }
}
