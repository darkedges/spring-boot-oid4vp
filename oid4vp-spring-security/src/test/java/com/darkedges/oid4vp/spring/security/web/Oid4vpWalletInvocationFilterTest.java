package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.spring.security.registration.InMemoryOid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** {@link Oid4vpWalletInvocationFilter} redirects to a registration's configured
 * {@code walletAuthorizationEndpoint} with {@code client_id}/{@code request_uri} attached, and never
 * accepts a caller-supplied redirect target (open redirect). */
class Oid4vpWalletInvocationFilterTest {

    private static final RequestMatcher REQUEST_MATCHER =
            PathPatternRequestMatcher.pathPattern(Oid4vpWalletInvocationFilter.DEFAULT_INVOKE_URI_PATTERN);
    private static final String REQUEST_URI_BASE = "https://verifier.example.org/oid4vp/request";

    private static DcqlQuery sampleDcqlQuery() {
        return DcqlQuery.of(List.of(CredentialQuery.builder("pid", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://credentials.example.com/identity_credential")))
                .build()));
    }

    private static Oid4vpRelyingPartyRegistrationRepository registrations(Optional<URI> walletAuthorizationEndpoint) {
        Oid4vpRelyingPartyRegistration registration = new Oid4vpRelyingPartyRegistration(
                "demo-verifier",
                new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                URI.create("https://verifier.example.org/oid4vp/response"),
                ResponseMode.DIRECT_POST,
                Oid4vpWalletInvocationFilterTest::sampleDcqlQuery,
                Optional.empty(),
                walletAuthorizationEndpoint);
        return new InMemoryOid4vpRelyingPartyRegistrationRepository(registration);
    }

    @Test
    void redirectsToTheConfiguredWalletAuthorizationEndpointWithClientIdAndRequestUri() throws Exception {
        Oid4vpWalletInvocationFilter filter = new Oid4vpWalletInvocationFilter(
                REQUEST_MATCHER,
                registrations(Optional.of(URI.create("https://wallet.example.com/authorize"))),
                REQUEST_URI_BASE);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/invoke/demo-verifier");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo(
                "https://wallet.example.com/authorize?client_id=x509_san_dns%3Averifier.example.org"
                        + "&request_uri=https%3A%2F%2Fverifier.example.org%2Foid4vp%2Frequest%2Fdemo-verifier");
    }

    @Test
    void appendsToAnAuthorizationEndpointThatAlreadyHasAQueryString() throws Exception {
        Oid4vpWalletInvocationFilter filter = new Oid4vpWalletInvocationFilter(
                REQUEST_MATCHER,
                registrations(Optional.of(URI.create("https://wallet.example.com/authorize?tenant=abc"))),
                REQUEST_URI_BASE);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/invoke/demo-verifier");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getRedirectedUrl()).startsWith("https://wallet.example.com/authorize?tenant=abc&client_id=");
    }

    @Test
    void returns501WhenNoWalletAuthorizationEndpointIsConfigured() throws Exception {
        Oid4vpWalletInvocationFilter filter =
                new Oid4vpWalletInvocationFilter(REQUEST_MATCHER, registrations(Optional.empty()), REQUEST_URI_BASE);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/invoke/demo-verifier");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(501);
    }

    @Test
    void unknownRegistrationReturns404() throws Exception {
        Oid4vpWalletInvocationFilter filter = new Oid4vpWalletInvocationFilter(
                REQUEST_MATCHER,
                registrations(Optional.of(URI.create("https://wallet.example.com/authorize"))),
                REQUEST_URI_BASE);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oid4vp/invoke/no-such-registration");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void nonMatchingPathFallsThroughTheFilterChain() throws Exception {
        Oid4vpWalletInvocationFilter filter = new Oid4vpWalletInvocationFilter(
                REQUEST_MATCHER,
                registrations(Optional.of(URI.create("https://wallet.example.com/authorize"))),
                REQUEST_URI_BASE);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/unrelated/path");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(response.getStatus()).isEqualTo(200); // MockHttpServletResponse default, untouched
    }
}
