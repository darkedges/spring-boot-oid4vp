package com.darkedges.oid4vp.demo.wallet;

import com.darkedges.oid4vp.core.dcql.eval.CredentialStore;
import com.darkedges.oid4vp.sdjwt.Disclosure;
import com.darkedges.oid4vp.sdjwt.SdJwtVcHeldCredential;
import com.fasterxml.jackson.databind.node.TextNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Self-issues one SD-JWT VC credential at startup (given_name/family_name selectively disclosable), so
 * the demo has something to present without needing a separate Issuer role/app. Not a pattern to copy
 * for a real Wallet — actual credential issuance is a whole separate protocol
 * (OpenID for Verifiable Credential Issuance) outside this project's scope.
 */
@Configuration
public class DemoCredentialConfig {

    private static final Logger log = LoggerFactory.getLogger(DemoCredentialConfig.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    @Bean
    public ECKey demoIssuerKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256).keyID("demo-issuer-1").generate();
    }

    @Bean
    public ECKey demoHolderKey() throws JOSEException {
        return new ECKeyGenerator(Curve.P_256).keyID("demo-holder-1").generate();
    }

    @Bean
    public SdJwtVcHeldCredential demoCredential(ECKey demoIssuerKey, ECKey demoHolderKey) throws JOSEException {
        Disclosure givenName = Disclosure.createObjectProperty(randomSalt(), "given_name", TextNode.valueOf("Jane"));
        Disclosure familyName = Disclosure.createObjectProperty(randomSalt(), "family_name", TextNode.valueOf("Demo"));

        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("http://localhost:8081")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(3600 * 24 * 365)))
                .claim("vct", DemoConstants.VCT)
                .claim("_sd", List.of(givenName.digest(), familyName.digest()))
                .claim("_sd_alg", "sha-256")
                .claim("cnf", Map.of("jwk", demoHolderKey.toPublicJWK().toJSONObject()))
                .build();

        SignedJWT issuerJwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(demoIssuerKey.getKeyID()).build(), claims);
        issuerJwt.sign(new ECDSASigner(demoIssuerKey));

        String issuance = issuerJwt.serialize() + "~" + givenName.rawBase64Url() + "~" + familyName.rawBase64Url() + "~";
        SdJwtVcHeldCredential credential = SdJwtVcHeldCredential.parse(issuance);
        log.info("Self-issued demo credential: vct={}, disclosable claims=[given_name, family_name]", DemoConstants.VCT);
        return credential;
    }

    @Bean
    public CredentialStore demoCredentialStore(SdJwtVcHeldCredential demoCredential) {
        return CredentialStore.of(List.of(demoCredential));
    }

    private static String randomSalt() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
