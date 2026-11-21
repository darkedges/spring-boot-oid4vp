package com.darkedges.oid4vc.tenancy;

import com.darkedges.oid4vc.tenancy.domains.DomainDirectory;
import com.darkedges.oid4vc.tenancy.web.TenantResolutionFilter;
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
