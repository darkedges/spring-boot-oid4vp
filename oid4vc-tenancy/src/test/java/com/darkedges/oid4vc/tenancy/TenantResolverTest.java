package com.darkedges.oid4vc.tenancy;

import com.darkedges.oid4vc.tenancy.TenantContext.Routing;
import com.darkedges.oid4vc.tenancy.domains.StaticDomainDirectory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class TenantResolverTest {

    private final InMemoryTenantRepository tenants = new InMemoryTenantRepository();
    private TenantResolver resolver;

    @BeforeEach
    void setUp() {
        tenants.save(Tenant.create("env-bank", "org-1", "bank"));
        tenants.save(Tenant.create("env-shop", "org-2", "shop"));
        tenants.save(Tenant.create("zkp", null, "zkp"));
        tenants.save(Tenant.create("env-off", "org-1", "off").withEnabled(false));
        resolver = resolver("zkp");
    }

    private TenantResolver resolver(String defaultTenant) {
        return new TenantResolver(tenants, new StaticDomainDirectory(Map.of("issuer.bank.example", "env-bank")),
                List.of("issuer.zkp.au", "localhost"), defaultTenant, true, null);
    }

    private Optional<TenantResolver.Resolution> resolve(String host, String path) {
        return resolver.resolve(new TenantResolver.Request(host, null, "https", null, path));
    }

    @Test
    void aPlatformSubdomainNamesTheTenantBySlug() {
        var r = resolve("bank.issuer.zkp.au", "/token").orElseThrow();
        assertThat(r.context().tenantId()).isEqualTo("env-bank");
        assertThat(r.context().routing()).isEqualTo(Routing.PLATFORM_SUBDOMAIN);
        assertThat(r.context().baseUrl()).isEqualTo("https://bank.issuer.zkp.au");
        assertThat(r.context().wellKnown("openid-credential-issuer")).isEqualTo("https://bank.issuer.zkp.au/.well-known/openid-credential-issuer");
        assertThat(r.path()).isEqualTo("/token");
    }

    @Test
    void aVerifiedCustomDomainNamesItsEnvironment() {
        var r = resolve("Issuer.Bank.Example.", "/credential").orElseThrow();
        assertThat(r.context().tenantId()).isEqualTo("env-bank");
        assertThat(r.context().routing()).isEqualTo(Routing.CUSTOM_DOMAIN);
        assertThat(r.path()).isEqualTo("/credential");
    }

    @Test
    void aPathOnThePlatformHostNamesTheTenantAndIsRemoved() {
        var r = resolve("issuer.zkp.au", "/t/shop/credential-offer/abc").orElseThrow();
        assertThat(r.context().tenantId()).isEqualTo("env-shop");
        assertThat(r.context().routing()).isEqualTo(Routing.PATH);
        assertThat(r.context().baseUrl()).isEqualTo("https://issuer.zkp.au/t/shop");
        assertThat(r.context().url("/token")).isEqualTo("https://issuer.zkp.au/t/shop/token");
        assertThat(r.path()).isEqualTo("/credential-offer/abc");

        assertThat(resolve("issuer.zkp.au", "/t/shop").orElseThrow().path()).isEqualTo("/");
    }

    @Test
    void theInsertedWellKnownFormNamesTheTenant() {
        var r = resolve("issuer.zkp.au", "/.well-known/openid-credential-issuer/t/shop").orElseThrow();
        assertThat(r.context().tenantId()).isEqualTo("env-shop");
        assertThat(r.path()).isEqualTo("/.well-known/openid-credential-issuer");
        assertThat(r.context().wellKnown("oauth-authorization-server")).isEqualTo("https://issuer.zkp.au/.well-known/oauth-authorization-server/t/shop");
    }

    @Test
    void thePlatformHostItselfServesTheDefaultTenantOrNothing() {
        var r = resolve("issuer.zkp.au", "/.well-known/openid-credential-issuer").orElseThrow();
        assertThat(r.context().tenantId()).isEqualTo("zkp");
        assertThat(r.context().routing()).isEqualTo(Routing.DEFAULT);
        assertThat(r.context().baseUrl()).isEqualTo("https://issuer.zkp.au");

        resolver = resolver(null);
        assertThat(resolve("issuer.zkp.au", "/token")).isEmpty();
    }

    @Test
    void unknownHostsSlugsAndDisabledTenantsHaveNoTenant() {
        assertThat(resolve("evil.example", "/token")).isEmpty();
        assertThat(resolve("nobody.issuer.zkp.au", "/token")).isEmpty();
        assertThat(resolve("issuer.zkp.au", "/t/nobody/token")).isEmpty();
        assertThat(resolve("off.issuer.zkp.au", "/token")).isEmpty();
        assertThat(resolve("issuer.zkp.au", "/t/off/token")).isEmpty();
        // Deeper subdomains are not platform subdomains.
        assertThat(resolve("a.bank.issuer.zkp.au", "/token")).isEmpty();
    }

    @Test
    void thePathFormIsOnlyUnderstoodOnThePlatformHost() {
        // On a tenant's own host, /t/shop is just a path of that tenant: it cannot reach another tenant.
        var r = resolve("bank.issuer.zkp.au", "/t/shop/token").orElseThrow();
        assertThat(r.context().tenantId()).isEqualTo("env-bank");
        assertThat(r.path()).isEqualTo("/t/shop/token");
        assertThat(resolve("issuer.bank.example", "/t/shop/token").orElseThrow().context().tenantId()).isEqualTo("env-bank");
    }

    @Test
    void aForwardedHostCountsOnlyWhenItIsOneOfTheDeploymentsHosts() {
        var viaProxy = resolver.resolve(new TenantResolver.Request("10.0.0.30:8092", "shop.issuer.zkp.au", "http", "https", "/token")).orElseThrow();
        assertThat(viaProxy.context().tenantId()).isEqualTo("env-shop");
        assertThat(viaProxy.context().baseUrl()).isEqualTo("https://shop.issuer.zkp.au");

        // A client naming a host that isn't the deployment's: ignored, the real Host decides.
        var spoofed = resolver.resolve(new TenantResolver.Request("bank.issuer.zkp.au", "attacker.example", "https", null, "/token")).orElseThrow();
        assertThat(spoofed.context().tenantId()).isEqualTo("env-bank");
        assertThat(spoofed.context().baseUrl()).isEqualTo("https://bank.issuer.zkp.au");

        // A proxy that isn't trusted: the header is ignored.
        var untrusted = new TenantResolver(tenants, StaticDomainDirectory.firstOf(List.of()), List.of("issuer.zkp.au"), null, false, null);
        assertThat(untrusted.resolve(new TenantResolver.Request("bank.issuer.zkp.au", "shop.issuer.zkp.au", "https", "http", "/"))
                .orElseThrow().context().tenantId()).isEqualTo("env-bank");
    }

    @Test
    void developmentHostsKeepTheirPort() {
        var r = resolver.resolve(new TenantResolver.Request("bank.localhost:8092", null, "http", null, "/token")).orElseThrow();
        assertThat(r.context().baseUrl()).isEqualTo("http://bank.localhost:8092");
        var p = resolver.resolve(new TenantResolver.Request("localhost:8092", null, "http", null, "/t/shop/nonce")).orElseThrow();
        assertThat(p.context().baseUrl()).isEqualTo("http://localhost:8092/t/shop");
        assertThat(p.context().wellKnown("openid-credential-issuer")).isEqualTo("http://localhost:8092/.well-known/openid-credential-issuer/t/shop");
    }

    @Test
    void slugsAreDnsLabelsAndSomeAreReserved() {
        assertThat(Slugs.isValid("bank-1")).isTrue();
        assertThat(Slugs.isValid("Bank")).isFalse();
        assertThat(Slugs.isValid("-bank")).isFalse();
        assertThat(Slugs.isValid("xn--bnk-sna")).isFalse();
        assertThat(Slugs.isValid("a".repeat(64))).isFalse();
        assertThat(Slugs.isAvailableForTenants("admin")).isFalse();
        assertThat(Slugs.isAvailableForTenants("bank")).isTrue();
    }

    @Test
    void twoTenantsCannotShareASlug() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> tenants.save(Tenant.create("env-other", "org-3", "bank")))
                .isInstanceOf(TenantRepository.SlugTakenException.class);
    }
}
