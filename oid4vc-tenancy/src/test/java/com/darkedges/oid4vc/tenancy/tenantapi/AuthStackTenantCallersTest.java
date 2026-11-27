package com.darkedges.oid4vc.tenancy.tenantapi;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tenant API callers: an application of the tenant's own AuthStack environment, and one the tenant lists. */
class AuthStackTenantCallersTest {

    static final ObjectMapper JSON = new ObjectMapper();
    HttpServer authstack;
    String api;
    final Map<String, JWKSet> keySets = new ConcurrentHashMap<>();
    RSAKey bankKey, shopKey;
    Tenant bank;
    AuthStackTenantCallers callers;

    @BeforeEach
    void setUp() throws Exception {
        bankKey = new RSAKeyGenerator(2048).keyID("bank-1").generate();
        shopKey = new RSAKeyGenerator(2048).keyID("shop-1").generate();
        keySets.put("env-bank", new JWKSet(bankKey.toPublicJWK()));
        keySets.put("env-shop", new JWKSet(shopKey.toPublicJWK()));
        authstack = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        // AuthStack publishes each environment's keys at /<envId>/as/jwks.
        authstack.createContext("/", exchange -> {
            String[] parts = exchange.getRequestURI().getPath().split("/");
            JWKSet set = parts.length == 4 && parts[2].equals("as") && parts[3].equals("jwks") ? keySets.get(parts[1]) : null;
            byte[] body = (set == null ? "{}" : set.toString()).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(set == null ? 404 : 200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        authstack.start();
        api = "http://127.0.0.1:" + authstack.getAddress().getPort();
        bank = Tenant.create("env-bank", "org-1", "bank").withSettings(settings(List.of("bank-worker")));
        callers = new AuthStackTenantCallers(URI.create(api));
    }

    @AfterEach
    void tearDown() {
        authstack.stop(0);
    }

    static ObjectNode settings(List<String> clients) {
        ObjectNode settings = JSON.createObjectNode();
        clients.forEach(settings.putObject("tenantApi").putArray("clients")::add);
        if (clients.isEmpty()) settings.putObject("tenantApi").putArray("clients");
        return settings;
    }

    /** A token as AuthStack's token endpoint issues to a worker of environment {@code env}, signed with {@code key}. */
    String token(RSAKey key, String env, String clientId, String type, Date expires) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(api + "/" + env + "/as")
                .claim("client_id", clientId).claim("clientId", clientId).claim("resourceId", clientId)
                .claim("environmentId", env).claim("organizationId", "org-1").claim("type", type)
                .issueTime(new Date()).expirationTime(expires).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    Date inAnHour() { return new Date(System.currentTimeMillis() + 3_600_000); }

    @Test
    void anApplicationOfTheTenantsEnvironmentThatTheTenantListsMayCall() throws Exception {
        var caller = callers.verify(token(bankKey, "env-bank", "bank-worker", "client_credentials", inAnHour()), bank);
        assertThat(caller).isEqualTo(new TenantCallers.TenantCaller("env-bank", "bank-worker"));
    }

    @Test
    void anotherEnvironmentsTokenIsRefusedEvenWithAListedClientId() throws Exception {
        String shops = token(shopKey, "env-shop", "bank-worker", "client_credentials", inAnHour());
        assertThatThrownBy(() -> callers.verify(shops, bank)).isInstanceOfSatisfying(TenantCallers.TenantCallerException.class, e -> assertThat(e.status()).isEqualTo(401));
    }

    @Test
    void aTokenThatClaimsTheTenantsEnvironmentButIsSignedByAnotherIsRefused() throws Exception {
        String forged = token(shopKey, "env-bank", "bank-worker", "client_credentials", inAnHour());
        assertThatThrownBy(() -> callers.verify(forged, bank)).isInstanceOfSatisfying(TenantCallers.TenantCallerException.class, e -> assertThat(e.status()).isEqualTo(401));
    }

    @Test
    void aPersonsTokenIsNotAnApplications() throws Exception {
        String person = token(bankKey, "env-bank", "bank-worker", "authorization_code", inAnHour());
        assertThatThrownBy(() -> callers.verify(person, bank)).isInstanceOfSatisfying(TenantCallers.TenantCallerException.class, e -> assertThat(e.status()).isEqualTo(401));
    }

    @Test
    void anExpiredTokenAndNoTokenAreRefused() throws Exception {
        String expired = token(bankKey, "env-bank", "bank-worker", "client_credentials", new Date(System.currentTimeMillis() - 3_600_000));
        assertThatThrownBy(() -> callers.verify(expired, bank)).isInstanceOfSatisfying(TenantCallers.TenantCallerException.class, e -> assertThat(e.status()).isEqualTo(401));
        assertThatThrownBy(() -> callers.verify(null, bank)).isInstanceOfSatisfying(TenantCallers.TenantCallerException.class, e -> assertThat(e.status()).isEqualTo(401));
        assertThatThrownBy(() -> callers.verify("not-a-jwt", bank)).isInstanceOfSatisfying(TenantCallers.TenantCallerException.class, e -> assertThat(e.status()).isEqualTo(401));
    }

    @Test
    void onlyTheApplicationsTheTenantListsMayCall() throws Exception {
        String other = token(bankKey, "env-bank", "directory-worker", "client_credentials", inAnHour());
        assertThatThrownBy(() -> callers.verify(other, bank)).isInstanceOfSatisfying(TenantCallers.TenantCallerException.class, e -> {
            assertThat(e.status()).isEqualTo(403);
            assertThat(e.error()).isEqualTo("insufficient_scope");
        });
        // No list, or an empty one, allows nobody.
        String listed = token(bankKey, "env-bank", "bank-worker", "client_credentials", inAnHour());
        Tenant unlisted = Tenant.create("env-bank", "org-1", "bank");
        assertThatThrownBy(() -> callers.verify(listed, unlisted)).isInstanceOfSatisfying(TenantCallers.TenantCallerException.class, e -> assertThat(e.status()).isEqualTo(403));
        Tenant empty = bank.withSettings(settings(List.of()));
        assertThatThrownBy(() -> callers.verify(listed, empty)).isInstanceOfSatisfying(TenantCallers.TenantCallerException.class, e -> assertThat(e.status()).isEqualTo(403));
    }

    @Test
    void aRotatedKeyIsFetchedWhenATokenNamesIt() throws Exception {
        callers.verify(token(bankKey, "env-bank", "bank-worker", "client_credentials", inAnHour()), bank);
        RSAKey rotated = new RSAKeyGenerator(2048).keyID("bank-2").generate();
        keySets.put("env-bank", new JWKSet(List.of(bankKey.toPublicJWK(), rotated.toPublicJWK())));
        var caller = callers.verify(token(rotated, "env-bank", "bank-worker", "client_credentials", inAnHour()), bank);
        assertThat(caller.clientId()).isEqualTo("bank-worker");
    }
}
