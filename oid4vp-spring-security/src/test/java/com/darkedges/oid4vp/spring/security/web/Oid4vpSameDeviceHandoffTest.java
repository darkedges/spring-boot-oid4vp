package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationProvider;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.darkedges.oid4vp.verifier.AuthorizationResponseValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end same-device handoff: a successful {@code direct_post} response yields a {@code redirect_uri}
 * containing a {@code response_code} (rather than a bare {@code {}} ack), and hitting that URI via
 * {@link Oid4vpTransactionResultFilter} establishes the {@code SecurityContext} for that request.
 */
class Oid4vpSameDeviceHandoffTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String VCT = "https://credentials.example.com/example_credential";
    private static final String REGISTRATION_ID = "demo-verifier";
    private static final RequestMatcher RESPONSE_MATCHER = Oid4vpAuthorizationResponseAuthenticationFilter.defaultRequestMatcher();
    private static final RequestMatcher RESULT_MATCHER =
            PathPatternRequestMatcher.pathPattern(Oid4vpTransactionResultFilter.DEFAULT_RESULT_URI_PATTERN);

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> sdJwtVcldSettings() {
        return FixtureLoader.readYaml("examples/sd_jwt_vcld/settings.yml");
    }

    private static String verifierIdentifier() {
        return ((Map<String, Object>) sdJwtVcldSettings().get("identifiers")).get("verifier").toString();
    }

    private static String keyBindingNonce() {
        return sdJwtVcldSettings().get("key_binding_nonce").toString();
    }

    @SuppressWarnings("unchecked")
    private static IssuerKeyResolver issuerKeyResolver() throws Exception {
        Map<String, Object> keySettings = (Map<String, Object>) sdJwtVcldSettings().get("key_settings");
        Map<String, Object> issuerKeyYaml = ((List<Map<String, Object>>) keySettings.get("issuer_keys")).get(0);
        ECKey issuerKey = new ECKey.Builder(Curve.P_256,
                new Base64URL(issuerKeyYaml.get("x").toString()),
                new Base64URL(issuerKeyYaml.get("y").toString()))
                .build();
        JsonNode jwk = MAPPER.readTree(issuerKey.toJSONString());
        return (issuer, keyId, certificateChain) -> Optional.of(jwk);
    }

    private static Clock fixedClock() {
        return Clock.fixed(Instant.ofEpochSecond(1744743394L), ZoneOffset.UTC);
    }

    @Test
    void handshakeThroughRedirectUriEstablishesSecurityContext() throws Exception {
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        InMemoryOid4vpTransactionResultRepository transactionResultRepository = new InMemoryOid4vpTransactionResultRepository();
        String state = "handoff-state-1";
        String transactionId = "handoff-txn-1";

        DcqlQuery dcqlQuery = DcqlQuery.of(List.of(CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of(VCT)))
                .build()));
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, keyBindingNonce(),
                new ClientIdentifierPrefix.PreRegistered(verifierIdentifier()),
                dcqlQuery, URI.create("https://verifier.example.org/oid4vp/response"),
                Instant.now().plusSeconds(300), Optional.of(transactionId)));

        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));
        ProviderManager authenticationManager = new ProviderManager(
                new Oid4vpAuthorizationResponseAuthenticationProvider(validator, issuerKeyResolver(), fixedClock()));

        Oid4vpAuthorizationResponseAuthenticationConverter converter =
                new Oid4vpAuthorizationResponseAuthenticationConverter(requestRepository, RESPONSE_MATCHER, null);
        Oid4vpAuthorizationResponseAuthenticationFilter responseFilter =
                new Oid4vpAuthorizationResponseAuthenticationFilter(authenticationManager, RESPONSE_MATCHER, converter);
        responseFilter.setAuthenticationSuccessHandler(new Oid4vpSameDeviceAuthenticationSuccessHandler(
                transactionResultRepository, "https://verifier.example.org/oid4vp/result"));

        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        MockHttpServletRequest walletPost = new MockHttpServletRequest("POST", "/login/oid4vp/direct-post/" + REGISTRATION_ID);
        walletPost.addParameter("state", state);
        walletPost.addParameter("vp_token", "{\"my_credential\":[\"" + presentation + "\"]}");
        MockHttpServletResponse walletPostResponse = new MockHttpServletResponse();

        responseFilter.doFilter(walletPost, walletPostResponse, new MockFilterChain());

        assertThat(walletPostResponse.getStatus()).isEqualTo(200);
        JsonNode ackBody = MAPPER.readTree(walletPostResponse.getContentAsString());
        assertThat(ackBody.has("redirect_uri")).isTrue();
        String redirectUri = ackBody.get("redirect_uri").asText();
        assertThat(redirectUri).startsWith("https://verifier.example.org/oid4vp/result/" + transactionId + "?response_code=");

        Matcher matcher = Pattern.compile("response_code=(.+)$").matcher(redirectUri);
        assertThat(matcher.find()).isTrue();
        String responseCode = matcher.group(1);

        // The End-User's browser follows the redirect.
        Oid4vpTransactionResultFilter resultFilter = new Oid4vpTransactionResultFilter(RESULT_MATCHER, transactionResultRepository);
        MockHttpServletRequest browserGet =
                new MockHttpServletRequest("GET", "/oid4vp/result/" + transactionId);
        browserGet.setParameter("response_code", responseCode);
        MockHttpServletResponse browserGetResponse = new MockHttpServletResponse();

        resultFilter.doFilter(browserGet, browserGetResponse, new MockFilterChain());

        assertThat(browserGetResponse.getStatus()).isEqualTo(200);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isInstanceOf(Oid4vpAuthenticationToken.class);
        Oid4vpPrincipal principal = (Oid4vpPrincipal) authentication.getPrincipal();
        assertThat(principal.claim("my_credential", "ld", "credentialSubject", "givenName"))
                .hasValueSatisfying(node -> assertThat(node.asText()).isEqualTo("John"));

        // The transaction/response_code are single-use.
        MockHttpServletRequest replay = new MockHttpServletRequest("GET", "/oid4vp/result/" + transactionId);
        replay.setParameter("response_code", responseCode);
        MockHttpServletResponse replayResponse = new MockHttpServletResponse();
        resultFilter.doFilter(replay, replayResponse, new MockFilterChain());
        assertThat(replayResponse.getStatus()).isEqualTo(404);
    }

    @Test
    void plainDirectPostWithoutTransactionIdStillGetsABareAck() throws Exception {
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        InMemoryOid4vpTransactionResultRepository transactionResultRepository = new InMemoryOid4vpTransactionResultRepository();
        String state = "handoff-state-2";

        DcqlQuery dcqlQuery = DcqlQuery.of(List.of(CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of(VCT)))
                .build()));
        // No transactionId this time.
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, keyBindingNonce(),
                new ClientIdentifierPrefix.PreRegistered(verifierIdentifier()),
                dcqlQuery, URI.create("https://verifier.example.org/oid4vp/response"),
                Instant.now().plusSeconds(300)));

        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));
        ProviderManager authenticationManager = new ProviderManager(
                new Oid4vpAuthorizationResponseAuthenticationProvider(validator, issuerKeyResolver(), fixedClock()));
        Oid4vpAuthorizationResponseAuthenticationConverter converter =
                new Oid4vpAuthorizationResponseAuthenticationConverter(requestRepository, RESPONSE_MATCHER, null);
        Oid4vpAuthorizationResponseAuthenticationFilter responseFilter =
                new Oid4vpAuthorizationResponseAuthenticationFilter(authenticationManager, RESPONSE_MATCHER, converter);
        responseFilter.setAuthenticationSuccessHandler(new Oid4vpSameDeviceAuthenticationSuccessHandler(
                transactionResultRepository, "https://verifier.example.org/oid4vp/result"));

        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        MockHttpServletRequest walletPost = new MockHttpServletRequest("POST", "/login/oid4vp/direct-post/" + REGISTRATION_ID);
        walletPost.addParameter("state", state);
        walletPost.addParameter("vp_token", "{\"my_credential\":[\"" + presentation + "\"]}");
        MockHttpServletResponse walletPostResponse = new MockHttpServletResponse();

        responseFilter.doFilter(walletPost, walletPostResponse, new MockFilterChain());

        assertThat(walletPostResponse.getContentAsString()).isEqualTo("{}");
    }

    @Test
    void resultFilterRedirectsToConfiguredUriInsteadOfBareAckWhenConfigured() throws Exception {
        InMemoryOid4vpTransactionResultRepository transactionResultRepository = new InMemoryOid4vpTransactionResultRepository();
        String transactionId = "handoff-txn-redirect";
        String responseCode = "code-1";
        transactionResultRepository.save(transactionId, responseCode,
                new TestingAuthenticationToken("user", "credentials"));

        Oid4vpTransactionResultFilter resultFilter =
                new Oid4vpTransactionResultFilter(RESULT_MATCHER, transactionResultRepository, "/");
        MockHttpServletRequest browserGet = new MockHttpServletRequest("GET", "/oid4vp/result/" + transactionId);
        browserGet.setParameter("response_code", responseCode);
        MockHttpServletResponse browserGetResponse = new MockHttpServletResponse();

        resultFilter.doFilter(browserGet, browserGetResponse, new MockFilterChain());

        assertThat(browserGetResponse.getStatus()).isEqualTo(302);
        assertThat(browserGetResponse.getRedirectedUrl()).isEqualTo("/");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isInstanceOf(TestingAuthenticationToken.class);
    }
}
