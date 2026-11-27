package com.darkedges.oid4vc.tenancy.tenantapi;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tenant API callers are applications of the tenant's own AuthStack environment, presenting a client-credentials access token.
 *
 * <p>For a tenant (an environment) {@code E}, a token is accepted only if:
 * <ul>
 *   <li>it is signed (RS256) by a key of {@code E}: from {@code <api>/E/as/jwks}, so a token of any other environment fails the signature,
 *       not only a claim comparison;</li>
 *   <li>{@code iss} is {@code <api>/E/as}, it is unexpired, {@code type} is {@code client_credentials} and {@code environmentId} is {@code E};</li>
 *   <li>its {@code client_id} is listed in the tenant's settings, {@code tenantApi.clients}. Any application of the environment could
 *       otherwise call; an empty or missing list allows nobody.</li>
 * </ul>
 * The keys of each environment are fetched once and cached, and refreshed when a token names a key not seen yet (rotation).
 */
public final class AuthStackTenantCallers implements TenantCallers {

    private final String apiBase;
    private final Map<String, DefaultJWTProcessor<SecurityContext>> processors = new ConcurrentHashMap<>();

    /** @param authstackApi AuthStack's API origin, such as {@code https://api.authstack.darkedges.com} */
    public AuthStackTenantCallers(URI authstackApi) {
        this.apiBase = authstackApi.toString().replaceAll("/+$", "");
    }

    @Override
    public TenantCaller verify(String bearerToken, Tenant tenant) {
        if (bearerToken == null || bearerToken.isBlank()) throw new TenantCallerException(401, "A bearer token of the tenant's environment is required");
        JWTClaimsSet claims;
        try {
            claims = processorFor(tenant.id()).process(bearerToken, null);
        } catch (TenantCallerException e) {
            throw e;
        } catch (Exception e) {
            throw new TenantCallerException(401, "The token is not a valid token of this tenant's environment");
        }
        String clientId;
        try {
            clientId = claims.getStringClaim("client_id");
        } catch (java.text.ParseException e) {
            clientId = null;
        }
        if (clientId == null || clientId.isBlank()) throw new TenantCallerException(401, "The token names no client_id");
        if (!allowedClients(tenant).contains(clientId)) {
            throw new TenantCallerException(403, "This application may not call the tenant API (tenantApi.clients)");
        }
        return new TenantCaller(tenant.id(), clientId);
    }

    /** The applications a tenant lets call its tenant APIs: {@code settings.tenantApi.clients}. */
    static Set<String> allowedClients(Tenant tenant) {
        Set<String> clients = new HashSet<>();
        JsonNode list = tenant.settings() == null ? null : tenant.settings().path("tenantApi").path("clients");
        if (list != null && list.isArray()) list.forEach(c -> { if (c.isTextual() && !c.asText().isBlank()) clients.add(c.asText()); });
        return clients;
    }

    private DefaultJWTProcessor<SecurityContext> processorFor(String environmentId) {
        if (environmentId == null || !environmentId.matches("[A-Za-z0-9-]{1,64}")) {
            throw new TenantCallerException(401, "This tenant has no AuthStack environment to check tokens against");
        }
        return processors.computeIfAbsent(environmentId, this::newProcessor);
    }

    private DefaultJWTProcessor<SecurityContext> newProcessor(String environmentId) {
        String issuer = apiBase + "/" + environmentId + "/as";
        URL jwks;
        try {
            jwks = URI.create(issuer + "/jwks").toURL();
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(e);
        }
        JWKSource<SecurityContext> keys = JWKSourceBuilder.create(jwks).build();
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keys));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder()
                        .issuer(issuer)
                        .claim("type", "client_credentials")
                        .claim("environmentId", environmentId)
                        .build(),
                Set.of("exp", "client_id")));
        return processor;
    }
}
