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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

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
                List.of());
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
}
