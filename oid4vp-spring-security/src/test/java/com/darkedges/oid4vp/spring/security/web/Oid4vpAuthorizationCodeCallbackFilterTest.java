package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.core.request.TokenEndpointClient;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationProvider;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.darkedges.oid4vp.spring.security.registration.CodeFlowConfig;
import com.darkedges.oid4vp.spring.security.registration.InMemoryOid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.darkedges.oid4vp.verifier.AuthorizationResponseValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** End-to-end Authorization Code Grant callback: {@code ?code=...&state=...} is exchanged via a
 * {@link TokenEndpointClient}, the resulting {@code vp_token} goes through the exact same validation path
 * as {@code direct_post} ({@link Oid4vpAuthorizationResponseAuthenticationProvider}), and establishes the
 * {@code SecurityContext} on success — no code_verifier ever leaves the server. */
class Oid4vpAuthorizationCodeCallbackFilterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String VCT = "https://credentials.example.com/example_credential";
    private static final String REGISTRATION_ID = "conformancecode";
    private static final RequestMatcher CALLBACK_MATCHER = Oid4vpAuthorizationCodeCallbackFilter.defaultRequestMatcher();

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

    private static Oid4vpRelyingPartyRegistration registration() {
        DcqlQuery dcqlQuery = DcqlQuery.of(List.of(CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of(VCT)))
                .build()));
        return new Oid4vpRelyingPartyRegistration(
                REGISTRATION_ID,
                new ClientIdentifierPrefix.PreRegistered(verifierIdentifier()),
                URI.create("https://verifier.example.org/unused-response-uri"),
                ResponseMode.DIRECT_POST,
                () -> dcqlQuery,
                Optional.empty(),
                Optional.empty(),
                List.of(),
                Optional.of(new CodeFlowConfig(
                        URI.create("https://verifier.example.org/oid4vp/callback/" + REGISTRATION_ID),
                        Optional.of(URI.create("https://wallet.example.com/token")))));
    }

    private static ProviderManager authenticationManager() throws Exception {
        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));
        return new ProviderManager(new Oid4vpAuthorizationResponseAuthenticationProvider(validator, issuerKeyResolver(), fixedClock()));
    }

    @Test
    void successfulCodeExchangeEstablishesTheSecurityContext() throws Exception {
        Oid4vpRelyingPartyRegistration registration = registration();
        Oid4vpRelyingPartyRegistrationRepository registrations = new InMemoryOid4vpRelyingPartyRegistrationRepository(registration);
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();

        String state = "callback-state-1";
        String codeVerifier = "test-code-verifier";
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, keyBindingNonce(), registration.clientId(), registration.dcqlQuery().get(),
                registration.responseUri(), Instant.now().plusSeconds(300), Optional.empty(), Optional.of(codeVerifier)));

        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        JsonNode tokenResponse = MAPPER.readTree("{\"vp_token\":{\"my_credential\":[\"" + presentation + "\"]}}");

        AtomicReference<String> exchangedCode = new AtomicReference<>();
        TokenEndpointClient tokenEndpointClient = (tokenEndpoint, code, redirectUri, clientId, codeVerifierArg) -> {
            exchangedCode.set(code);
            assertThat(codeVerifierArg).isEqualTo(codeVerifier);
            assertThat(tokenEndpoint).isEqualTo(URI.create("https://wallet.example.com/token"));
            return tokenResponse;
        };

        Oid4vpAuthorizationCodeCallbackFilter filter = new Oid4vpAuthorizationCodeCallbackFilter(
                CALLBACK_MATCHER, authenticationManager(), requestRepository, registrations, tokenEndpointClient, null);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/callback/" + REGISTRATION_ID);
        request.setParameter("code", "fake-authorization-code");
        request.setParameter("state", state);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(exchangedCode.get()).isEqualTo("fake-authorization-code");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isInstanceOf(Oid4vpAuthenticationToken.class);
        Oid4vpPrincipal principal = (Oid4vpPrincipal) authentication.getPrincipal();
        assertThat(principal.claim("my_credential", "ld", "credentialSubject", "givenName"))
                .hasValueSatisfying(node -> assertThat(node.asText()).isEqualTo("John"));
    }

    @Test
    void redirectsToTheConfiguredSuccessUriInsteadOfWritingJson() throws Exception {
        Oid4vpRelyingPartyRegistration registration = registration();
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        String state = "callback-state-2";
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, keyBindingNonce(), registration.clientId(), registration.dcqlQuery().get(),
                registration.responseUri(), Instant.now().plusSeconds(300), Optional.empty(), Optional.of("verifier")));

        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        JsonNode tokenResponse = MAPPER.readTree("{\"vp_token\":{\"my_credential\":[\"" + presentation + "\"]}}");
        TokenEndpointClient tokenEndpointClient = (tokenEndpoint, code, redirectUri, clientId, codeVerifierArg) -> tokenResponse;

        Oid4vpAuthorizationCodeCallbackFilter filter = new Oid4vpAuthorizationCodeCallbackFilter(
                CALLBACK_MATCHER, authenticationManager(), requestRepository,
                new InMemoryOid4vpRelyingPartyRegistrationRepository(registration), tokenEndpointClient, "/");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/callback/" + REGISTRATION_ID);
        request.setParameter("code", "fake-authorization-code");
        request.setParameter("state", state);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo("/");
    }

    @Test
    void walletErrorParameterFailsWithoutCallingTheTokenEndpoint() throws Exception {
        Oid4vpRelyingPartyRegistration registration = registration();
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        String state = "callback-state-3";
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, keyBindingNonce(), registration.clientId(), registration.dcqlQuery().get(),
                registration.responseUri(), Instant.now().plusSeconds(300), Optional.empty(), Optional.of("verifier")));

        AtomicBoolean tokenEndpointCalled = new AtomicBoolean(false);
        TokenEndpointClient tokenEndpointClient = (tokenEndpoint, code, redirectUri, clientId, codeVerifierArg) -> {
            tokenEndpointCalled.set(true);
            throw new AssertionError("token endpoint must not be called when the Wallet reported an error");
        };

        Oid4vpAuthorizationCodeCallbackFilter filter = new Oid4vpAuthorizationCodeCallbackFilter(
                CALLBACK_MATCHER, authenticationManager(), requestRepository,
                new InMemoryOid4vpRelyingPartyRegistrationRepository(registration), tokenEndpointClient, null);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/callback/" + REGISTRATION_ID);
        request.setParameter("error", "access_denied");
        request.setParameter("state", state);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(tokenEndpointCalled.get()).isFalse();
    }

    @Test
    void missingWalletTokenEndpointFailsCleanlyWithoutCallingTheClient() throws Exception {
        // redirect-uri is always set for a code-flow registration, but wallet-token-endpoint legitimately
        // starts unset (e.g. before a conformance test run is started) — must fail with a clear message,
        // not NPE or silently behave like a vp_token registration.
        DcqlQuery dcqlQuery = DcqlQuery.of(List.of(CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of(VCT)))
                .build()));
        Oid4vpRelyingPartyRegistration registration = new Oid4vpRelyingPartyRegistration(
                REGISTRATION_ID,
                new ClientIdentifierPrefix.PreRegistered(verifierIdentifier()),
                URI.create("https://verifier.example.org/unused-response-uri"),
                ResponseMode.DIRECT_POST,
                () -> dcqlQuery,
                Optional.empty(),
                Optional.empty(),
                List.of(),
                Optional.of(new CodeFlowConfig(
                        URI.create("https://verifier.example.org/oid4vp/callback/" + REGISTRATION_ID),
                        Optional.empty())));

        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        String state = "callback-state-5";
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, keyBindingNonce(), registration.clientId(), registration.dcqlQuery().get(),
                registration.responseUri(), Instant.now().plusSeconds(300), Optional.empty(), Optional.of("verifier")));

        TokenEndpointClient tokenEndpointClient = (tokenEndpoint, code, redirectUri, clientId, codeVerifierArg) -> {
            throw new AssertionError("token endpoint must not be called when wallet-token-endpoint isn't configured");
        };

        Oid4vpAuthorizationCodeCallbackFilter filter = new Oid4vpAuthorizationCodeCallbackFilter(
                CALLBACK_MATCHER, authenticationManager(), requestRepository,
                new InMemoryOid4vpRelyingPartyRegistrationRepository(registration), tokenEndpointClient, null);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/callback/" + REGISTRATION_ID);
        request.setParameter("code", "fake-authorization-code");
        request.setParameter("state", state);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void unknownOrExpiredStateFailsCleanly() throws Exception {
        Oid4vpRelyingPartyRegistration registration = registration();
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        TokenEndpointClient tokenEndpointClient = (tokenEndpoint, code, redirectUri, clientId, codeVerifierArg) -> {
            throw new AssertionError("token endpoint must not be called for an unknown state");
        };

        Oid4vpAuthorizationCodeCallbackFilter filter = new Oid4vpAuthorizationCodeCallbackFilter(
                CALLBACK_MATCHER, authenticationManager(), requestRepository,
                new InMemoryOid4vpRelyingPartyRegistrationRepository(registration), tokenEndpointClient, null);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/callback/" + REGISTRATION_ID);
        request.setParameter("code", "fake-authorization-code");
        request.setParameter("state", "no-such-state");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void tokenResponseWithoutVpTokenFailsCleanly() throws Exception {
        Oid4vpRelyingPartyRegistration registration = registration();
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        String state = "callback-state-4";
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, keyBindingNonce(), registration.clientId(), registration.dcqlQuery().get(),
                registration.responseUri(), Instant.now().plusSeconds(300), Optional.empty(), Optional.of("verifier")));

        TokenEndpointClient tokenEndpointClient = (tokenEndpoint, code, redirectUri, clientId, codeVerifierArg) -> MAPPER.createObjectNode();

        Oid4vpAuthorizationCodeCallbackFilter filter = new Oid4vpAuthorizationCodeCallbackFilter(
                CALLBACK_MATCHER, authenticationManager(), requestRepository,
                new InMemoryOid4vpRelyingPartyRegistrationRepository(registration), tokenEndpointClient, null);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/callback/" + REGISTRATION_ID);
        request.setParameter("code", "fake-authorization-code");
        request.setParameter("state", state);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
    }
}
