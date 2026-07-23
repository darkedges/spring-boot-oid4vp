package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.spring.security.registration.InMemoryOid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** End-to-end: GET/POST to the hosted request_uri endpoint returns a signed Request Object with the
 * required {@code oauth-authz-req+jwt} type, correct content type, and (for POST) an echoed
 * {@code wallet_nonce}. */
class Oid4vpRequestObjectFilterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final RequestMatcher REQUEST_MATCHER =
            PathPatternRequestMatcher.pathPattern(Oid4vpRequestObjectFilter.DEFAULT_REQUEST_URI_PATTERN);

    private static Oid4vpAuthorizationRequestService requestService(ECKey signingKey) {
        DcqlQuery dcqlQuery = DcqlQuery.of(List.of(CredentialQuery.builder("pid", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://credentials.example.com/identity_credential")))
                .build()));
        Oid4vpRelyingPartyRegistration registration = new Oid4vpRelyingPartyRegistration(
                "demo-verifier",
                new ClientIdentifierPrefix.RedirectUri("https://verifier.example.org/oid4vp/response"),
                URI.create("https://verifier.example.org/oid4vp/response"),
                ResponseMode.DIRECT_POST,
                () -> dcqlQuery,
                Optional.empty(),
                Optional.empty(),
                List.of(),
                Optional.empty());
        return new Oid4vpAuthorizationRequestService(
                new InMemoryOid4vpRelyingPartyRegistrationRepository(registration),
                new InMemoryOid4vpAuthorizationRequestRepository(),
                Clock.systemUTC(),
                Duration.ofMinutes(10));
    }

    private static RequestObjectSigningKeyResolver signingKeyResolver(ECKey signingKey) throws Exception {
        JsonNode privateJwk = MAPPER.readTree(signingKey.toJSONString());
        return registrationId -> "demo-verifier".equals(registrationId) ? Optional.of(privateJwk) : Optional.empty();
    }

    @Test
    void getReturnsASignedRequestObject() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256).keyID("verifier-sign-1").generate();
        Oid4vpRequestObjectFilter filter = new Oid4vpRequestObjectFilter(
                REQUEST_MATCHER, requestService(signingKey), signingKeyResolver(signingKey), JWSAlgorithm.ES256);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/request/demo-verifier");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).isEqualTo(Oid4vpRequestObjectFilter.CONTENT_TYPE);

        SignedJWT jwt = SignedJWT.parse(response.getContentAsString());
        assertThat(jwt.getHeader().getType().getType()).isEqualTo("oauth-authz-req+jwt");
        assertThat(jwt.verify(new ECDSAVerifier(signingKey.toECPublicKey()))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getStringClaim("client_id"))
                .isEqualTo("redirect_uri:https://verifier.example.org/oid4vp/response");
        assertThat(jwt.getJWTClaimsSet().getClaim("wallet_nonce")).isNull();
    }

    @Test
    void postEchoesWalletNonce() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256).generate();
        Oid4vpRequestObjectFilter filter = new Oid4vpRequestObjectFilter(
                REQUEST_MATCHER, requestService(signingKey), signingKeyResolver(signingKey), JWSAlgorithm.ES256);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oid4vp/request/demo-verifier");
        request.addParameter("wallet_nonce", "wallet-supplied-nonce");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        SignedJWT jwt = SignedJWT.parse(response.getContentAsString());
        assertThat(jwt.getJWTClaimsSet().getStringClaim("wallet_nonce")).isEqualTo("wallet-supplied-nonce");
    }

    @Test
    void unknownRegistrationReturns404() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256).generate();
        Oid4vpRequestObjectFilter filter = new Oid4vpRequestObjectFilter(
                REQUEST_MATCHER, requestService(signingKey), signingKeyResolver(signingKey), JWSAlgorithm.ES256);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/request/no-such-registration");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void nonMatchingPathFallsThroughTheFilterChain() throws Exception {
        ECKey signingKey = new ECKeyGenerator(Curve.P_256).generate();
        Oid4vpRequestObjectFilter filter = new Oid4vpRequestObjectFilter(
                REQUEST_MATCHER, requestService(signingKey), signingKeyResolver(signingKey), JWSAlgorithm.ES256);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/unrelated/path");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(response.getStatus()).isEqualTo(200); // MockHttpServletResponse default, untouched
        assertThat(response.getContentAsString()).isEmpty();
    }
}
