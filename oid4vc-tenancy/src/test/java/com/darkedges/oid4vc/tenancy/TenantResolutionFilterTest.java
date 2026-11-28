package com.darkedges.oid4vc.tenancy;

import com.darkedges.oid4vc.tenancy.domains.DomainDirectory;
import com.darkedges.oid4vc.tenancy.web.TenantResolutionFilter;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TenantResolutionFilterTest {

    private final InMemoryTenantRepository tenants = new InMemoryTenantRepository();
    private final TenantResolutionFilter filter;

    TenantResolutionFilterTest() {
        tenants.save(Tenant.create("env-shop", "org-2", "shop"));
        filter = new TenantResolutionFilter(
                new TenantResolver(tenants, DomainDirectory.NONE, List.of("issuer.zkp.au"), null, true, null),
                List.of("/admin/api/**", "/error"));
    }

    private static MockHttpServletRequest request(String host, String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        request.addHeader("Host", host);
        request.setServerName(host);
        request.setScheme("https");
        return request;
    }

    @Test
    void theApplicationSeesTheSingleTenantPathAndTheTenant() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request("issuer.zkp.au", "/t/shop/credential"), response, chain);

        HttpServletRequest seen = (HttpServletRequest) chain.getRequest();
        assertThat(seen.getRequestURI()).isEqualTo("/credential");
        assertThat(seen.getServletPath()).isEqualTo("/credential");
        assertThat(seen.getRequestURL().toString()).endsWith("/credential");
        assertThat(TenantContext.require(seen).baseUrl()).isEqualTo("https://issuer.zkp.au/t/shop");
    }

    @Test
    void theInsertedWellKnownIsServedAsTheRootWellKnown() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request("issuer.zkp.au", "/.well-known/openid-credential-issuer/t/shop"), new MockHttpServletResponse(), chain);
        assertThat(((HttpServletRequest) chain.getRequest()).getRequestURI()).isEqualTo("/.well-known/openid-credential-issuer");
    }

    @Test
    void aForwardOrErrorDispatchSeesWhereItWasSentNotTheOriginalPath() throws Exception {
        for (DispatcherType dispatch : List.of(DispatcherType.FORWARD, DispatcherType.ERROR)) {
            MockHttpServletRequest original = request("issuer.zkp.au", "/t/shop/");
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(original, new MockHttpServletResponse(), chain);
            HttpServletRequest seen = (HttpServletRequest) chain.getRequest();
            assertThat(seen.getServletPath()).isEqualTo("/");

            // The container keeps this wrapper and changes the request beneath it: a forward has to see where it was sent.
            original.setDispatcherType(dispatch);
            original.setRequestURI("/index.html");
            original.setServletPath("/index.html");
            assertThat(seen.getRequestURI()).isEqualTo("/index.html");
            assertThat(seen.getServletPath()).isEqualTo("/index.html");
            assertThat(seen.getRequestURL().toString()).endsWith("/index.html");
            assertThat(TenantContext.require(seen).baseUrl()).isEqualTo("https://issuer.zkp.au/t/shop");
        }
    }

    @Test
    void aRelativeDispatchIsResolvedAgainstThePathTheApplicationSees() throws Exception {
        for (String[] each : new String[][] {{"/t/shop/", "/index.html"}, {"/t/shop", "/index.html"}, {"/t/shop/demo/page", "/demo/index.html"}}) {
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(request("issuer.zkp.au", each[0]), new MockHttpServletResponse(), chain);
            MockHttpServletResponse forwarded = new MockHttpServletResponse();
            HttpServletRequest seen = (HttpServletRequest) chain.getRequest();
            seen.getRequestDispatcher("index.html").forward(seen, forwarded);
            assertThat(forwarded.getForwardedUrl()).as(each[0]).isEqualTo(each[1]);
        }
    }

    @Test
    void aRequestWithNoTenantIsNotFound() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request("issuer.zkp.au", "/token"), response, chain);
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(chain.getRequest()).isNull();
    }

    @Test
    void platformPathsAreServedWithoutATenant() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request("issuer.zkp.au", "/admin/api/tenants"), response, chain);
        assertThat(chain.getRequest()).isNotNull();
        assertThat(TenantContext.from((HttpServletRequest) chain.getRequest())).isEmpty();
        // A look-alike is not a platform path.
        MockFilterChain other = new MockFilterChain();
        filter.doFilter(request("issuer.zkp.au", "/admin/apix"), new MockHttpServletResponse(), other);
        assertThat(other.getRequest()).isNull();
    }
}
