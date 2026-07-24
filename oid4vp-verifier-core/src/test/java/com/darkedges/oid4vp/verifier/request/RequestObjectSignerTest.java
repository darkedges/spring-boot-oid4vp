package com.darkedges.oid4vp.verifier.request;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.AuthorizationRequest;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.RequestUriMethod;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class RequestObjectSignerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static AuthorizationRequest sampleRequest() {
        DcqlQuery dcqlQuery = DcqlQuery.of(List.of(CredentialQuery.builder("pid", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://credentials.example.com/identity_credential")))
                .build()));
        return new AuthorizationRequest(
                "vp_token",
                new ClientIdentifierPrefix.RedirectUri("https://verifier.example.org/oid4vp/response"),
                ResponseMode.DIRECT_POST,
                Optional.of("https://verifier.example.org/oid4vp/response"),
                Optional.empty(),
                Optional.of(dcqlQuery),
                Optional.empty(),
                Optional.of("some-state"),
                "some-nonce",
                Optional.empty(),
                RequestUriMethod.GET,
                List.of(),
                List.of(),
                Optional.empty(),
                Optional.empty());
    }

    @Test
    void signsARequestObjectWithTheRequiredTypeHeaderAndClaims() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256).keyID("verifier-sign-1").generate();
        JsonNode privateJwk = MAPPER.readTree(signingKey.toJSONString());

        SignedJWT jwt = RequestObjectSigner.sign(sampleRequest(), privateJwk, JWSAlgorithm.ES256, Optional.empty());

        assertThat(jwt.getHeader().getType().getType()).isEqualTo(RequestObjectSigner.TYPE);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("verifier-sign-1");
        assertThat(jwt.verify(new ECDSAVerifier(signingKey.toECPublicKey()))).isTrue();

        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertThat(claims.getStringClaim("response_type")).isEqualTo("vp_token");
        assertThat(claims.getStringClaim("client_id")).isEqualTo("redirect_uri:https://verifier.example.org/oid4vp/response");
        assertThat(claims.getStringClaim("response_mode")).isEqualTo("direct_post");
        assertThat(claims.getStringClaim("response_uri")).isEqualTo("https://verifier.example.org/oid4vp/response");
        assertThat(claims.getStringClaim("nonce")).isEqualTo("some-nonce");
        assertThat(claims.getStringClaim("state")).isEqualTo("some-state");
        assertThat(claims.getClaim("wallet_nonce")).isNull();

        // dcql_query round-trips through the claim set correctly.
        JsonNode dcqlQueryClaim = MAPPER.valueToTree(claims.getClaim("dcql_query"));
        assertThat(dcqlQueryClaim.get("credentials").get(0).get("id").asText()).isEqualTo("pid");
    }

    @Test
    void echoesWalletNonceWhenProvided() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256).generate();
        JsonNode privateJwk = MAPPER.readTree(signingKey.toJSONString());

        SignedJWT jwt = RequestObjectSigner.sign(sampleRequest(), privateJwk, JWSAlgorithm.ES256, Optional.of("wallet-provided-nonce"));

        assertThat(jwt.getJWTClaimsSet().getStringClaim("wallet_nonce")).isEqualTo("wallet-provided-nonce");
    }

    // A throwaway self-signed EC key + matching cert (openssl req -x509 ..., PKCS12), checked in as a test
    // resource — Nimbus's ECKey.Builder validates that an x5c entry's public key matches the JWK's own,
    // so a real cert whose keypair we don't otherwise have is rejected.
    //
    // Built via plain java.security.KeyStore rather than Nimbus's own ECKey.load(KeyStore, ...): that
    // convenience method reaches for org.bouncycastle.cert.jcajce.JcaX509CertificateHolder internally,
    // and this project deliberately has no BouncyCastle dependency (JDK 21's native EC support is enough
    // everywhere else) — not worth pulling one in just for this helper.
    private static ECKey loadTestSigningKeyWithCertChain() throws Exception {
        char[] password = "changeit".toCharArray();
        String alias = "test-signing";
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = RequestObjectSignerTest.class.getResourceAsStream("/test-signing-key.p12")) {
            keyStore.load(in, password);
        }

        ECPrivateKey privateKey = (ECPrivateKey) keyStore.getKey(alias, password);
        Certificate[] chain = keyStore.getCertificateChain(alias);
        ECPublicKey publicKey = (ECPublicKey) chain[0].getPublicKey();
        List<Base64> x5c = Arrays.stream(chain)
                .map(cert -> {
                    try {
                        return Base64.encode(cert.getEncoded());
                    } catch (CertificateEncodingException e) {
                        throw new IllegalStateException(e);
                    }
                })
                .toList();

        return new ECKey.Builder(Curve.P_256, publicKey)
                .privateKey(privateKey)
                .x509CertChain(x5c)
                .build();
    }

    @Test
    void carriesAnX509CertChainFromTheSigningKeyIntoTheJwsHeader() throws Exception {
        ECKey signingKey = loadTestSigningKeyWithCertChain();
        List<Base64> certChain = signingKey.getX509CertChain();
        assertThat(certChain).isNotEmpty();
        JsonNode privateJwk = MAPPER.readTree(signingKey.toJSONString());

        SignedJWT jwt = RequestObjectSigner.sign(sampleRequest(), privateJwk, JWSAlgorithm.ES256, Optional.empty());

        assertThat(jwt.getHeader().getX509CertChain()).isEqualTo(certChain);
        assertThat(jwt.verify(new ECDSAVerifier(signingKey.toECPublicKey()))).isTrue();
    }

    @Test
    void omitsX509CertChainHeaderWhenTheSigningKeyHasNone() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256).generate();
        JsonNode privateJwk = MAPPER.readTree(signingKey.toJSONString());

        SignedJWT jwt = RequestObjectSigner.sign(sampleRequest(), privateJwk, JWSAlgorithm.ES256, Optional.empty());

        assertThat(jwt.getHeader().getX509CertChain()).isNull();
    }
}
