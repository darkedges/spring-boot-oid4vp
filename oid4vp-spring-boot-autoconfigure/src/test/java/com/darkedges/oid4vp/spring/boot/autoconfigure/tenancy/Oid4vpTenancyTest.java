package com.darkedges.oid4vp.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.InMemoryTenantRepository;
import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantContext;
import com.darkedges.oid4vc.tenancy.admin.TenantSettingsValidator;
import com.darkedges.oid4vc.tenancy.autoconfigure.TenancyAutoConfiguration;
import com.darkedges.oid4vc.tenancy.keys.InMemoryTenantKeyRepository;
import com.darkedges.oid4vc.tenancy.keys.TenantCertificateAuthority;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.http.HttpClient;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class Oid4vpTenancyTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DCQL = "{\"credentials\":[{\"id\":\"employee\",\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"https://vct.example/employee\"]}}]}";

    private final InMemoryTenantRepository tenants = new InMemoryTenantRepository();
    private final TenantKeyService keys = new TenantKeyService(new InMemoryTenantKeyRepository(),
            TenantCertificateAuthority.selfSigned(Duration.ofDays(30)), Set.of("request-object"));
    private final Oid4vpTenancy tenancy = new Oid4vpTenancy(tenants, keys, "irving", "/login/oid4vp/direct-post/",
            HttpClient.newHttpClient(), Clock.systemUTC());
    private final ECKey trustedIssuerKey;
    private final Tenant bank;
    private final Tenant shop;

    Oid4vpTenancyTest() throws Exception {
        trustedIssuerKey = new ECKeyGenerator(Curve.P_256).keyID("issuer-key").generate();
        ObjectNode bankSettings = (ObjectNode) MAPPER.readTree("""
                {"registrations":{"login":{"dcqlQuery":%s,"walletAuthorizationEndpoint":"openid4vp://authorize"}},
                 "trustedIssuers":[{"issuer":"https://issuer.zkp.au/t/bank","jwks":{"keys":[%s]}}],
                 "dcApiAllowedOrigins":["https://app.bank.example"]}
                """.formatted(DCQL, trustedIssuerKey.toPublicJWK().toJSONString()));
        bank = tenants.save(Tenant.create("env-bank", "org-1", "bank").withSettings(bankSettings));
        shop = tenants.save(Tenant.create("env-shop", "org-2", "shop").withSettings((ObjectNode) MAPPER.readTree(
                "{\"registrations\":{\"login\":{\"dcqlQuery\":" + DCQL + "}}}")));
        tenants.save(Tenant.create("irving", null, "irving"));
    }

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
    }

    private static MockHttpServletRequest at(Tenant tenant) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(TenantContext.ATTRIBUTE, new TenantContext(tenant, TenantContext.Routing.PATH, "https", "verifier.zkp.au",
                "/t/" + tenant.slug()));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return request;
    }

    @Test
    void theDefaultTenantKeepsThePlainIdsAndOthersAreScoped() {
        assertThat(tenancy.tenantResolver().tenantId(at(tenants.findById("irving").orElseThrow()))).isEqualTo("default");
        assertThat(tenancy.tenantResolver().registrationKey(at(bank), "login")).isEqualTo("env-bank/login");
    }

    @Test
    void aTenantsRegistrationIsItsOwnOnItsOwnUrlWithItsOwnClientId() throws Exception {
        Oid4vpRelyingPartyRegistration appRegistration = null;
        var registrations = tenancy.registrations(key -> Optional.ofNullable(key.equals("login") ? appRegistration : null));

        at(bank);
        Oid4vpRelyingPartyRegistration bankLogin = registrations.findByRegistrationId("env-bank/login").orElseThrow();
        assertThat(bankLogin.responseUri().toString()).isEqualTo("https://verifier.zkp.au/t/bank/login/oid4vp/direct-post/login");
        assertThat(bankLogin.walletAuthorizationEndpoint()).isPresent();

        // Its client id is the hash of the certificate of the key that signs its requests.
        ECKey signing = ECKey.parse(tenancy.requestObjectSigningKeys(null).resolveSigningKey("env-bank/login").orElseThrow().toString());
        byte[] der = Base64.getDecoder().decode(signing.getX509CertChain().get(0).toString());
        String hash = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(der)).toString();
        assertThat(bankLogin.clientId()).isEqualTo(new ClientIdentifierPrefix.X509Hash(hash));

        // Another tenant's registration of the same name is different, and not found on the bank's URLs.
        assertThat(registrations.findByRegistrationId("env-shop/login")).isEmpty();
        at(shop);
        Oid4vpRelyingPartyRegistration shopLogin = registrations.findByRegistrationId("env-shop/login").orElseThrow();
        assertThat(shopLogin.clientId()).isNotEqualTo(bankLogin.clientId());
        assertThat(registrations.findByRegistrationId("env-shop/nobody")).isEmpty();
    }

    @Test
    void eachTenantTrustsOnlyTheIssuersItLists() {
        var trust = tenancy.issuerTrust((issuer, kid, chain) -> Optional.empty());
        assertThat(trust.forTenant("env-bank").resolve("https://issuer.zkp.au/t/bank", Optional.of("issuer-key"), List.of())).isPresent();
        assertThat(trust.forTenant("env-bank").resolve("https://issuer.elsewhere.example", Optional.of("issuer-key"), List.of())).isEmpty();
        // The shop lists no issuers, so the bank's issuer doesn't satisfy it.
        assertThat(trust.forTenant("env-shop").resolve("https://issuer.zkp.au/t/bank", Optional.of("issuer-key"), List.of())).isEmpty();
    }

    @Test
    void aTrustAnchorVouchesOnlyForLeavesItIssued() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair caKeys = generator.generateKeyPair();
        var caCert = TenantCertificateAuthority.selfSigned(Duration.ofDays(30)).issue(caKeys, "platform", "ca", "ca");
        var ca = TenantCertificateAuthority.of(caKeys.getPrivate(), caCert, Duration.ofDays(30));
        KeyPair leafKeys = generator.generateKeyPair();
        String leaf = Base64.getEncoder().encodeToString(ca.issue(leafKeys, "env-x", "x", "issuer-signing").getEncoded());
        String stranger = Base64.getEncoder().encodeToString(TenantCertificateAuthority.selfSigned(Duration.ofDays(30))
                .issue(generator.generateKeyPair(), "env-y", "y", "issuer-signing").getEncoded());
        String pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(caCert.getEncoded()) + "\n-----END CERTIFICATE-----";

        var resolver = new TrustListIssuerKeyResolver(TrustListIssuerKeyResolver.read(MAPPER.readTree(
                "[{\"issuer\":\"https://issuer.zkp.au\",\"x5cTrustAnchors\":[" + MAPPER.writeValueAsString(pem) + "]}]")),
                HttpClient.newHttpClient(), Clock.systemUTC());
        assertThat(resolver.resolve("https://issuer.zkp.au", Optional.empty(), List.of(leaf))).isPresent();
        assertThat(resolver.resolve("https://issuer.zkp.au", Optional.empty(), List.of(stranger))).isEmpty();
    }

    @Test
    void theDcApiAcceptsATenantsOwnOriginAndTheOnesItLists() {
        var policy = tenancy.dcApiOriginPolicy();
        assertThat(policy.allows(at(bank), "env-bank/login", "https://verifier.zkp.au")).isTrue();
        assertThat(policy.allows(at(bank), "env-bank/login", "https://app.bank.example")).isTrue();
        assertThat(policy.allows(at(bank), "env-bank/login", "https://attacker.example")).isFalse();
        assertThat(policy.allows(at(bank), "login", "https://anything.example")).as("the default tenant, as before").isTrue();
    }

    @Test
    void urlsAreTheTenantsOwnOrTheDeploymentsForTheDefaultTenant() {
        var requestUri = tenancy.url("/oid4vp/request", "https://verify.irving.au/oid4vp/request");
        assertThat(requestUri.apply(at(bank))).isEqualTo("https://verifier.zkp.au/t/bank/oid4vp/request");
        assertThat(requestUri.apply(at(tenants.findById("irving").orElseThrow()))).isEqualTo("https://verify.irving.au/oid4vp/request");
    }

    @Test
    void settingsThatWouldNotWorkAreRefused() throws Exception {
        assertThat(Oid4vpTenancy.TenantVerifierSettings.problems(MAPPER.readTree("{}"))).isEmpty();
        assertThat(Oid4vpTenancy.TenantVerifierSettings.problems(MAPPER.readTree("{\"registrations\":{\"x\":{\"dcqlQuery\":{}}}}"))).isNotEmpty();
        assertThat(Oid4vpTenancy.TenantVerifierSettings.problems(MAPPER.readTree("{\"trustedIssuers\":[{\"issuer\":\"https://i\"}]}"))).isNotEmpty();
        assertThat(Oid4vpTenancy.TenantVerifierSettings.problems(MAPPER.readTree(
                "{\"trustedIssuers\":[{\"issuer\":\"https://i\",\"jwks\":{\"keys\":[" + new ECKeyGenerator(Curve.P_256).generate().toJSONString() + "]}}]}")))
                .anySatisfy(p -> assertThat(p).contains("public"));
        assertThat(Oid4vpTenancy.TenantVerifierSettings.problems(MAPPER.readTree("{\"dcApiAllowedOrigins\":[\"https://a.example/path\"]}"))).isNotEmpty();
    }

    @Test
    void theAutoConfigurationProvidesTheTenancyAndValidatesVerifierSettings() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Oid4vpVerifierTenancyAutoConfiguration.class, TenancyAutoConfiguration.class))
                .withPropertyValues("oid4vc.tenancy.enabled=true", "oid4vc.tenancy.service=verifier", "oid4vc.tenancy.store.type=memory",
                        "oid4vc.tenancy.platform-origins=https://verifier.zkp.au", "oid4vc.tenancy.authstack.api-url=https://authstack.example",
                        "oid4vc.tenancy.default-tenant.id=irving")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(Oid4vpTenancy.class).hasSingleBean(TenantSettingsValidator.class);
                    assertThat(context.getBean(TenantSettingsValidator.class).validate((ObjectNode) MAPPER.readTree(
                            "{\"registrations\":{\"x\":{\"dcqlQuery\":{}}}}"))).isNotEmpty();
                });
        // Off without tenancy.
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(Oid4vpVerifierTenancyAutoConfiguration.class))
                .run(context -> assertThat(context).doesNotHaveBean(Oid4vpTenancy.class));
    }
}
