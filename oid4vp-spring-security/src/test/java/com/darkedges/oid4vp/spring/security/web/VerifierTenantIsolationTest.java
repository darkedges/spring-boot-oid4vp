package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.RequestUriMethod;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationException;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRegistrationKey;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Two tenants, each with a registration called "login": a request, a response, a key or a result of one tenant is never found from
 * the other, while a single-tenant verifier keeps its plain registration ids.
 */
class VerifierTenantIsolationTest {

    /** Tenant by host, as the tenancy filter resolves it: bank.verifier.test and shop.verifier.test. */
    private static final Oid4vpTenantResolver BY_HOST = request -> request.getServerName().split("\\.")[0];

    private static Oid4vpRelyingPartyRegistration registration(String key) {
        String tenant = Oid4vpRegistrationKey.tenantOf(key);
        DcqlQuery dcql = DcqlQuery.of(List.of(CredentialQuery.builder("employee", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://vct.example/employee"))).build()));
        return new Oid4vpRelyingPartyRegistration(key, new ClientIdentifierPrefix.X509Hash("hash-of-" + tenant),
                URI.create("https://" + tenant + ".verifier.test/login/oid4vp/direct-post/login"), ResponseMode.DIRECT_POST,
                () -> dcql, Optional.empty(), Optional.empty(), List.of(), Optional.empty(), RequestUriMethod.GET);
    }

    /** Registrations by key, as a tenant-aware repository holds them. */
    private final Oid4vpRelyingPartyRegistrationRepository registrations = key ->
            List.of("bank/login", "shop/login", "login").contains(key) ? Optional.of(registration(key)) : Optional.empty();

    private final InMemoryOid4vpAuthorizationRequestRepository contexts = new InMemoryOid4vpAuthorizationRequestRepository();
    private final Oid4vpAuthorizationRequestService requests = new Oid4vpAuthorizationRequestService(
            registrations, contexts, new InMemoryOid4vpEphemeralEncryptionKeyRepository(), Clock.systemUTC(), Duration.ofMinutes(5));

    private static MockHttpServletRequest at(String tenant, String method, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServerName(tenant + ".verifier.test");
        return request;
    }

    private Oid4vpAuthorizationResponseAuthenticationConverter converter() {
        var converter = new Oid4vpAuthorizationResponseAuthenticationConverter(
                contexts, Oid4vpAuthorizationResponseAuthenticationFilter.defaultRequestMatcher(), null);
        converter.setTenantResolver(BY_HOST);
        return converter;
    }

    private static MockHttpServletRequest response(String tenant, String state) {
        MockHttpServletRequest post = at(tenant, "POST", "/login/oid4vp/direct-post/login");
        post.setParameter("state", state);
        post.setParameter("vp_token", "{\"employee\":[\"x\"]}");
        return post;
    }

    @Test
    void registrationKeysAreScopedToTheirTenantAndPlainForTheDefaultTenant() {
        assertThat(Oid4vpRegistrationKey.of("bank", "login")).isEqualTo("bank/login");
        assertThat(Oid4vpRegistrationKey.of(Oid4vpRegistrationKey.DEFAULT_TENANT, "login")).isEqualTo("login");
        assertThat(Oid4vpRegistrationKey.tenantOf("bank/login")).isEqualTo("bank");
        assertThat(Oid4vpRegistrationKey.tenantOf("login")).isEqualTo(Oid4vpRegistrationKey.DEFAULT_TENANT);
        assertThat(Oid4vpRegistrationKey.registrationIdOf("bank/login")).isEqualTo("login");
        assertThatThrownBy(() -> Oid4vpRegistrationKey.of("bank", "shop/login")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aResponseToOneTenantsRequestIsRefusedAtAnotherTenantsEndpointOfTheSameName() {
        String state = requests.resolve(BY_HOST.registrationKey(at("bank", "GET", "/"), "login")).request().state().orElseThrow();

        assertThatThrownBy(() -> converter().convert(response("shop", state))).isInstanceOf(Oid4vpAuthenticationException.class);
        var token = converter().convert(response("bank", state));
        assertThat(token.requestContext().registrationId()).isEqualTo("bank/login");
    }

    @Test
    void theRequestObjectAndItsKeysAreTheTenantsOwn() throws Exception {
        List<String> signingKeysAskedFor = new ArrayList<>();
        Oid4vpRequestObjectFilter filter = new Oid4vpRequestObjectFilter(
                PathPatternRequestMatcher.pathPattern(Oid4vpRequestObjectFilter.DEFAULT_REQUEST_URI_PATTERN), requests,
                key -> { signingKeysAskedFor.add(key); return Optional.empty(); }, com.nimbusds.jose.JWSAlgorithm.ES256);
        filter.setTenantResolver(BY_HOST);

        filter.doFilter(at("shop", "GET", "/oid4vp/request/login"), new MockHttpServletResponse(), new MockFilterChain());
        assertThat(signingKeysAskedFor).containsExactly("shop/login");
        // An unknown registration at a tenant isn't found.
        MockHttpServletResponse unknown = new MockHttpServletResponse();
        filter.doFilter(at("shop", "GET", "/oid4vp/request/nobody"), unknown, new MockFilterChain());
        assertThat(unknown.getStatus()).isEqualTo(404);
    }

    @Test
    void aSameDeviceResultIsCollectedOnlyAtTheTenantThePresentationWasMadeTo() throws Exception {
        var results = new InMemoryOid4vpTransactionResultRepository();
        var handler = new Oid4vpSameDeviceAuthenticationSuccessHandler(results,
                request -> "https://" + request.getServerName() + "/oid4vp/result");
        Oid4vpAuthenticationToken authenticated = new Oid4vpAuthenticationToken(new Oid4vpPrincipal(Map.of()), AuthorityUtils.NO_AUTHORITIES, "tx-1");
        authenticated.setRegistrationKey("bank/login");
        assertThat(authenticated.tenantId()).isEqualTo("bank");
        assertThat(authenticated.registrationId()).isEqualTo("login");

        MockHttpServletResponse posted = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(response("bank", "s"), posted, authenticated);
        String redirect = new com.fasterxml.jackson.databind.ObjectMapper().readTree(posted.getContentAsString()).path("redirect_uri").asText();
        assertThat(redirect).startsWith("https://bank.verifier.test/oid4vp/result/tx-1?response_code=");
        String code = redirect.substring(redirect.indexOf("response_code=") + "response_code=".length());

        var resultFilter = new Oid4vpTransactionResultFilter(
                PathPatternRequestMatcher.pathPattern(Oid4vpTransactionResultFilter.DEFAULT_RESULT_URI_PATTERN), results);
        resultFilter.setTenantResolver(BY_HOST);
        MockHttpServletRequest atShop = at("shop", "GET", "/oid4vp/result/tx-1");
        atShop.setParameter("response_code", code);
        MockHttpServletResponse shopResponse = new MockHttpServletResponse();
        resultFilter.doFilter(atShop, shopResponse, new MockFilterChain());
        assertThat(shopResponse.getStatus()).isEqualTo(404);

        MockHttpServletRequest atBank = at("bank", "GET", "/oid4vp/result/tx-1");
        atBank.setParameter("response_code", code);
        MockHttpServletResponse bankResponse = new MockHttpServletResponse();
        resultFilter.doFilter(atBank, bankResponse, new MockFilterChain());
        assertThat(bankResponse.getStatus()).isEqualTo(200);
    }

    @Test
    void theDcApiRefusesAnOriginTheTenantDoesNotAllow() {
        String state = requests.resolve("bank/login").request().state().orElseThrow();
        var converter = new Oid4vpDcApiAuthenticationConverter(contexts,
                Oid4vpAuthorizationResponseAuthenticationFilter.defaultDcApiRequestMatcher(), null);
        converter.setTenantResolver(BY_HOST);
        converter.setOriginPolicy((request, key, origin) -> origin.equals("https://" + Oid4vpRegistrationKey.tenantOf(key) + ".verifier.test"));

        MockHttpServletRequest relayed = at("bank", "POST", "/login/oid4vp/dc-api/login");
        relayed.addHeader("Origin", "https://attacker.example");
        relayed.setContentType("application/json");
        relayed.setContent(("{\"state\":\"" + state + "\",\"vp_token\":{\"employee\":[\"x\"]}}").getBytes());
        assertThatThrownBy(() -> converter.convert(relayed)).isInstanceOf(Oid4vpAuthenticationException.class).hasMessageContaining("origin");

        MockHttpServletRequest own = at("bank", "POST", "/login/oid4vp/dc-api/login");
        own.addHeader("Origin", "https://bank.verifier.test");
        own.setContentType("application/json");
        own.setContent(("{\"state\":\"" + state + "\",\"vp_token\":{\"employee\":[\"x\"]}}").getBytes());
        assertThat(converter.convert(own).audienceOverride()).contains("origin:https://bank.verifier.test");
    }

    @Test
    void aSingleTenantVerifierKeepsItsPlainRegistrationIds() {
        String state = requests.resolve("login").request().state().orElseThrow();
        var converter = new Oid4vpAuthorizationResponseAuthenticationConverter(
                contexts, Oid4vpAuthorizationResponseAuthenticationFilter.defaultRequestMatcher(), null);
        assertThat(converter.convert(response("any", state)).requestContext().registrationId()).isEqualTo("login");
    }

    @Test
    void aPresentationIsVerifiedAgainstTheIssuersItsOwnTenantTrusts() {
        List<String> trustAskedFor = new ArrayList<>();
        var provider = new com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationProvider(
                new com.darkedges.oid4vp.verifier.AuthorizationResponseValidator(Map.of()),
                tenantId -> { trustAskedFor.add(tenantId); return (issuer, kid, chain) -> Optional.empty(); },
                null, Clock.systemUTC());
        String state = requests.resolve("bank/login").request().state().orElseThrow();
        var token = converter().convert(response("bank", state));
        assertThatThrownBy(() -> provider.authenticate(token)).isInstanceOf(Oid4vpAuthenticationException.class);
        assertThat(trustAskedFor).containsExactly("bank");
    }
}
