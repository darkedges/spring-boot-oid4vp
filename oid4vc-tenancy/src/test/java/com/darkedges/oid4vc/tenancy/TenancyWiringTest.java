package com.darkedges.oid4vc.tenancy;

import com.darkedges.oid4vc.tenancy.admin.TenantAdminController;
import com.darkedges.oid4vc.tenancy.autoconfigure.TenancyAutoConfiguration;
import com.darkedges.oid4vc.tenancy.domains.DomainDirectory;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.darkedges.oid4vc.tenancy.web.TenantResolutionFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class TenancyWiringTest {

    /** A single-tenant controller, unaware of tenants beyond reading the context. */
    @RestController
    static class TokenController {
        @GetMapping("/token")
        String token(HttpServletRequest request) {
            return TenantContext.require(request).url("/token");
        }

        @GetMapping("/.well-known/openid-credential-issuer")
        String metadata(HttpServletRequest request) {
            return TenantContext.require(request).baseUrl();
        }
    }

    @Test
    void springMvcRoutesTenantPathsToSingleTenantMappings() throws Exception {
        InMemoryTenantRepository tenants = new InMemoryTenantRepository();
        tenants.save(Tenant.create("env-shop", "org-2", "shop"));
        TenantResolver resolver = new TenantResolver(tenants, DomainDirectory.NONE, List.of("issuer.zkp.au"), null, true, null);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new TokenController())
                .addFilters(new TenantResolutionFilter(resolver, List.of("/admin/api/**"))).build();

        mvc.perform(get("/t/shop/token").header("Host", "issuer.zkp.au").header("X-Forwarded-Proto", "https"))
                .andExpect(status().isOk()).andExpect(content().string("https://issuer.zkp.au/t/shop/token"));
        mvc.perform(get("/token").header("Host", "shop.issuer.zkp.au").header("X-Forwarded-Proto", "https"))
                .andExpect(status().isOk()).andExpect(content().string("https://shop.issuer.zkp.au/token"));
        mvc.perform(get("/.well-known/openid-credential-issuer/t/shop").header("Host", "issuer.zkp.au").header("X-Forwarded-Proto", "https"))
                .andExpect(status().isOk()).andExpect(content().string("https://issuer.zkp.au/t/shop"));
        mvc.perform(get("/token").header("Host", "issuer.zkp.au")).andExpect(status().isNotFound());
    }

    @Test
    void theAutoConfigurationIsOffUnlessEnabled() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(TenancyAutoConfiguration.class))
                .run(context -> assertThat(context).doesNotHaveBean(TenantResolver.class));
    }

    @Test
    void theAutoConfigurationWiresTheResolverKeysAndAdminApi() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(TenancyAutoConfiguration.class))
                .withPropertyValues(
                        "oid4vc.tenancy.enabled=true",
                        "oid4vc.tenancy.store.type=memory",
                        "oid4vc.tenancy.platform-origins=https://issuer.zkp.au",
                        "oid4vc.tenancy.default-tenant.id=zkp",
                        "oid4vc.tenancy.authstack.api-url=https://auth.example")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(TenantResolver.class).hasSingleBean(TenantKeyService.class)
                            .hasSingleBean(TenantAdminController.class);
                    assertThat(context).getBean("tenantResolutionFilter").isNotNull();
                    // The default tenant exists and is served on the platform host.
                    TenantResolver resolver = context.getBean(TenantResolver.class);
                    assertThat(resolver.resolve(new TenantResolver.Request("issuer.zkp.au", null, "https", null, "/token")))
                            .get().extracting(r -> r.context().tenantId()).isEqualTo("zkp");
                });
    }

    @Test
    void theJdbcStoreRefusesToStartWithoutADataSourceOrKey() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(TenancyAutoConfiguration.class))
                .withPropertyValues("oid4vc.tenancy.enabled=true", "oid4vc.tenancy.platform-origins=https://issuer.zkp.au",
                        "oid4vc.tenancy.admin.enabled=false")
                .run(context -> assertThat(context).hasFailed().getFailure().hasStackTraceContaining("needs a DataSource"));
    }
}
