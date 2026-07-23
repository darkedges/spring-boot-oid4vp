package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.sdjwt.KbJwtBuilder;
import com.darkedges.oid4vp.sdjwt.SdJwt;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationProvider;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.darkedges.oid4vp.verifier.AuthorizationResponseValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A page's relay of a Digital Credentials API result: a same-origin JSON POST carrying
 * {@code {"vp_token": {...}, "state": "..."}}, with the audience bound to {@code origin:<Origin header>}
 * rather than a {@code client_id} (OpenID4VP 1.1, "OpenID4VP over the Digital Credentials API").
 *
 * <p>Builds its own SD-JWT VC presentation (issuer + holder EC keys generated on the fly) rather than
 * reusing the {@code sd_jwt_vcld/01} fixture, since that fixture's Key Binding JWT is bound to a
 * different audience ({@code https://verifier.example.org}, not {@code origin:https://verifier.example.org}).
 */
class Oid4vpDcApiAuthenticationConverterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String VCT = "https://credentials.example.com/example_credential";
    private static final String REGISTRATION_ID = "demo-verifier";
    private static final String ORIGIN = "https://verifier.example.org";
    private static final RequestMatcher REQUEST_MATCHER =
            PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login/oid4vp/dc-api/{registrationId}");

    private static Clock fixedClock() {
        return Clock.fixed(Instant.ofEpochSecond(1744743394L), ZoneOffset.UTC);
    }

    private static MockHttpServletRequest jsonPostRequest(String path, String origin, String jsonBody) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.setContentType("application/json");
        request.setContent(jsonBody.getBytes(StandardCharsets.UTF_8));
        if (origin != null) {
            request.addHeader("Origin", origin);
        }
        return request;
    }

    /** Builds a minimal SD-JWT VC presentation (no selectively-disclosed claims, one mandatory
     * {@code given_name} claim) with a Key Binding JWT bound to the given {@code nonce}/{@code aud}. */
    private static String buildPresentation(ECKey issuerKey, ECKey holderKey, String nonce, String aud) throws Exception {
        Instant iat = fixedClock().instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://issuer.example.com")
                .issueTime(Date.from(iat))
                .expirationTime(Date.from(iat.plusSeconds(3600)))
                .claim("vct", VCT)
                .claim("given_name", "John")
                .claim("cnf", Map.of("jwk", holderKey.toPublicJWK().toJSONObject()))
                .build();
        SignedJWT issuerJwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        issuerJwt.sign(new ECDSASigner(issuerKey));

        SdJwt sdJwt = new SdJwt(issuerJwt, List.of(), Optional.empty());
        String withoutKeyBinding = sdJwt.toStringWithoutKeyBinding();

        SignedJWT kbJwt = KbJwtBuilder.build(
                withoutKeyBinding, nonce, aud, iat, JWSAlgorithm.ES256, new ECDSASigner(holderKey), Optional.empty(), Optional.empty());

        return withoutKeyBinding + kbJwt.serialize();
    }

    @Test
    void authenticatesAnOriginBoundDcApiResponse() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).generate();
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        String state = "dc-api-state-1";
        String nonce = "dc-api-nonce-1";
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, nonce,
                new ClientIdentifierPrefix.PreRegistered("irrelevant-for-dc-api"),
                DcqlQuery.of(List.of(CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                        .meta(new SdJwtVcMeta(List.of(VCT)))
                        .build())),
                URI.create("https://verifier.example.org/oid4vp/response"),
                Instant.now().plusSeconds(300)));

        String presentation = buildPresentation(issuerKey, holderKey, nonce, "origin:" + ORIGIN);
        String body = "{\"state\":\"" + state + "\",\"vp_token\":{\"my_credential\":[\"" + presentation + "\"]}}";

        MockHttpServletRequest request = jsonPostRequest("/login/oid4vp/dc-api/" + REGISTRATION_ID, ORIGIN, body);

        Oid4vpDcApiAuthenticationConverter converter =
                new Oid4vpDcApiAuthenticationConverter(requestRepository, REQUEST_MATCHER, null);
        Authentication unauthenticated = converter.convert(request);
        assertThat(((Oid4vpAuthorizationResponseAuthenticationToken) unauthenticated).audienceOverride())
                .contains("origin:" + ORIGIN);

        JsonNode issuerJwk = MAPPER.readTree(issuerKey.toPublicJWK().toJSONString());
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) -> Optional.of(issuerJwk);
        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));
        Oid4vpAuthorizationResponseAuthenticationProvider provider =
                new Oid4vpAuthorizationResponseAuthenticationProvider(validator, issuerKeyResolver, fixedClock());

        Authentication authenticated = provider.authenticate(unauthenticated);

        assertThat(authenticated).isInstanceOf(Oid4vpAuthenticationToken.class);
        Oid4vpPrincipal principal = (Oid4vpPrincipal) authenticated.getPrincipal();
        assertThat(principal.claim("my_credential", "given_name"))
                .hasValueSatisfying(node -> assertThat(node.asText()).isEqualTo("John"));
    }

    @Test
    void authenticatesAnEncryptedDcApiResponse() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).generate();
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
        ECKey responseEncryptionKey = new ECKeyGenerator(Curve.P_256).keyID("dc-api-enc-1").generate();

        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        String state = "dc-api-encrypted-state-1";
        String nonce = "dc-api-encrypted-nonce-1";
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, nonce,
                new ClientIdentifierPrefix.PreRegistered("irrelevant-for-dc-api"),
                DcqlQuery.of(List.of(CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                        .meta(new SdJwtVcMeta(List.of(VCT)))
                        .build())),
                URI.create("https://verifier.example.org/oid4vp/response"),
                Instant.now().plusSeconds(300)));

        String presentation = buildPresentation(issuerKey, holderKey, nonce, "origin:" + ORIGIN);
        com.fasterxml.jackson.databind.node.ObjectNode payload = MAPPER.createObjectNode();
        payload.put("state", state);
        payload.putObject("vp_token").putArray("my_credential").add(presentation);

        com.nimbusds.jose.JWEHeader jweHeader = new com.nimbusds.jose.JWEHeader.Builder(
                com.nimbusds.jose.JWEAlgorithm.ECDH_ES, com.nimbusds.jose.EncryptionMethod.A128GCM)
                .keyID(responseEncryptionKey.getKeyID())
                .build();
        com.nimbusds.jose.JWEObject jwe = new com.nimbusds.jose.JWEObject(jweHeader, new com.nimbusds.jose.Payload(payload.toString()));
        jwe.encrypt(new com.nimbusds.jose.crypto.ECDHEncrypter(responseEncryptionKey.toPublicJWK()));

        String body = "{\"response\":\"" + jwe.serialize() + "\"}";
        MockHttpServletRequest request = jsonPostRequest("/login/oid4vp/dc-api/" + REGISTRATION_ID, ORIGIN, body);

        JsonNode privateJwks = MAPPER.valueToTree(
                new com.nimbusds.jose.jwk.JWKSet(responseEncryptionKey).toJSONObject(false));
        Oid4vpDcApiAuthenticationConverter converter = new Oid4vpDcApiAuthenticationConverter(
                requestRepository, REQUEST_MATCHER, registrationId -> Optional.of(privateJwks));

        Authentication unauthenticated = converter.convert(request);

        JsonNode issuerJwk = MAPPER.readTree(issuerKey.toPublicJWK().toJSONString());
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) -> Optional.of(issuerJwk);
        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));
        Oid4vpAuthorizationResponseAuthenticationProvider provider =
                new Oid4vpAuthorizationResponseAuthenticationProvider(validator, issuerKeyResolver, fixedClock());

        Authentication authenticated = provider.authenticate(unauthenticated);

        Oid4vpPrincipal principal = (Oid4vpPrincipal) authenticated.getPrincipal();
        assertThat(principal.claim("my_credential", "given_name"))
                .hasValueSatisfying(node -> assertThat(node.asText()).isEqualTo("John"));
    }

    @Test
    void rejectsMissingOriginHeader() {
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        MockHttpServletRequest request =
                jsonPostRequest("/login/oid4vp/dc-api/" + REGISTRATION_ID, null, "{\"state\":\"x\",\"vp_token\":{}}");

        Oid4vpDcApiAuthenticationConverter converter =
                new Oid4vpDcApiAuthenticationConverter(requestRepository, REQUEST_MATCHER, null);

        assertThatThrownBy(() -> converter.convert(request)).isInstanceOf(RuntimeException.class);
    }

    @Test
    void rejectsUnknownState() {
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        MockHttpServletRequest request = jsonPostRequest(
                "/login/oid4vp/dc-api/" + REGISTRATION_ID, ORIGIN, "{\"state\":\"never-issued\",\"vp_token\":{}}");

        Oid4vpDcApiAuthenticationConverter converter =
                new Oid4vpDcApiAuthenticationConverter(requestRepository, REQUEST_MATCHER, null);

        assertThatThrownBy(() -> converter.convert(request)).isInstanceOf(RuntimeException.class);
    }
}
