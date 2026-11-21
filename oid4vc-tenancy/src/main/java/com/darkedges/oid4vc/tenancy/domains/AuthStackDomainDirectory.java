package com.darkedges.oid4vc.tenancy.domains;

import com.darkedges.oid4vc.tenancy.Slugs;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Custom domains from AuthStack, the registry of every environment's domains: {@code GET /api/platform/domains?purpose=<purpose>}
 * lists the ACTIVE ones for this service ({@code issuer} or {@code verifier}) as {@code [{host, environmentId, organizationId}]}.
 *
 * <p>It is called with an access token of the platform's own worker (client credentials), which only that worker can obtain. The
 * list is cached for {@code refresh}; a host not in it triggers at most one early refresh per {@code missBackoff}, so a domain that
 * has just gone live is served quickly, and a flood of unknown hosts doesn't flood AuthStack. If AuthStack can't be reached, the last
 * list is kept.
 */
public final class AuthStackDomainDirectory implements DomainDirectory {

    private static final Logger log = LoggerFactory.getLogger(AuthStackDomainDirectory.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final URI domainsUri;
    private final URI tokenUri;
    private final String clientId;
    private final String clientSecret;
    private final Duration refresh;
    private final Duration missBackoff;
    private final HttpClient http;
    private final Clock clock;

    private volatile Map<String, DomainBinding> byHost = Map.of();
    private volatile Instant loadedAt = Instant.EPOCH;
    private volatile Instant lastMissRefresh = Instant.EPOCH;
    private volatile String accessToken;
    private volatile Instant accessTokenExpires = Instant.EPOCH;

    public AuthStackDomainDirectory(URI apiBaseUrl, String purpose, URI tokenUri, String clientId, String clientSecret,
                                    Duration refresh, Duration missBackoff, HttpClient http, Clock clock) {
        String base = apiBaseUrl.toString().replaceAll("/+$", "");
        this.domainsUri = URI.create(base + "/api/platform/domains?purpose=" + URLEncoder.encode(purpose, StandardCharsets.UTF_8));
        this.tokenUri = tokenUri;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.refresh = refresh;
        this.missBackoff = missBackoff;
        this.http = http;
        this.clock = clock;
    }

    @Override
    public Optional<DomainBinding> lookup(String host) {
        String wanted = Slugs.normalizeHost(host);
        if (wanted.isEmpty()) return Optional.empty();
        Instant now = clock.instant();
        Instant seen = loadedAt;
        if (now.isAfter(seen.plus(refresh))) seen = reload(now, seen);
        DomainBinding found = byHost.get(wanted);
        if (found == null && now.isAfter(lastMissRefresh.plus(missBackoff))) {
            lastMissRefresh = now;
            reload(now, seen);
            found = byHost.get(wanted);
        }
        return Optional.ofNullable(found);
    }

    /** Reloads, unless another thread reloaded since the caller last looked ({@code seen}). Returns when the list was loaded. */
    private synchronized Instant reload(Instant now, Instant seen) {
        if (!loadedAt.equals(seen)) return loadedAt;
        try {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(domainsUri)
                    .header("Authorization", "Bearer " + token(now))
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 401) accessToken = null; // fetch a new token next time
            if (response.statusCode() != 200) {
                log.warn("AuthStack domain directory answered {}; keeping the {} domains already known", response.statusCode(), byHost.size());
                loadedAt = now;
                return loadedAt;
            }
            byHost = parse(MAPPER.readTree(response.body()));
            loadedAt = now;
        } catch (Exception e) {
            log.warn("AuthStack domain directory unreachable ({}); keeping the {} domains already known", e.toString(), byHost.size());
            loadedAt = now;
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
        }
        return loadedAt;
    }

    static Map<String, DomainBinding> parse(JsonNode body) {
        JsonNode items = body.isArray() ? body : body.path("domains");
        Map<String, DomainBinding> result = new ConcurrentHashMap<>();
        for (JsonNode item : items) {
            String host = Slugs.normalizeHost(item.path("host").asText(""));
            String env = item.path("environmentId").asText("");
            if (host.isEmpty() || env.isEmpty()) continue;
            String org = item.hasNonNull("organizationId") ? item.get("organizationId").asText() : null;
            result.put(host, new DomainBinding(host, env, org));
        }
        return Map.copyOf(result);
    }

    private String token(Instant now) throws Exception {
        if (accessToken != null && now.isBefore(accessTokenExpires)) return accessToken;
        String basic = Base64.getEncoder().encodeToString(
                (URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8))
                        .getBytes(StandardCharsets.UTF_8));
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(tokenUri)
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials")).build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) throw new IllegalStateException("token endpoint answered " + response.statusCode());
        JsonNode body = MAPPER.readTree(response.body());
        accessToken = body.path("access_token").asText();
        accessTokenExpires = now.plusSeconds(Math.max(30, body.path("expires_in").asLong(300) - 30));
        return accessToken;
    }
}
