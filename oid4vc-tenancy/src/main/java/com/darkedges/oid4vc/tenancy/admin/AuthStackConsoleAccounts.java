package com.darkedges.oid4vc.tenancy.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Asks AuthStack who a console token belongs to ({@code GET /api/auth/me}) and believes only that answer, as the self-service hub
 * does. Answers are cached for a minute, keyed by a hash of the token (the token itself is not kept).
 */
public final class AuthStackConsoleAccounts implements ConsoleAccounts {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration CACHE = Duration.ofSeconds(60);

    private record Cached(ConsoleAccount account, Instant expires) {}

    private final URI meUri;
    private final HttpClient http;
    private final Clock clock;
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public AuthStackConsoleAccounts(URI consoleApiUrl, HttpClient http, Clock clock) {
        this.meUri = URI.create(consoleApiUrl.toString().replaceAll("/+$", "") + "/api/auth/me");
        this.http = http;
        this.clock = clock;
    }

    @Override
    public ConsoleAccount verify(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new ConsoleAccountException(401, "Sign in to the AuthStack console");
        }
        String key = sha256(bearerToken);
        Instant now = clock.instant();
        Cached cached = cache.get(key);
        if (cached != null && now.isBefore(cached.expires())) return cached.account();

        HttpResponse<String> response;
        try {
            response = http.send(HttpRequest.newBuilder(meUri)
                    .header("Authorization", "Bearer " + bearerToken)
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new ConsoleAccountException(503, "AuthStack could not be asked who you are");
        }
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            throw new ConsoleAccountException(401, "Your AuthStack console session has ended; sign in again");
        }
        if (response.statusCode() != 200) {
            throw new ConsoleAccountException(503, "AuthStack answered " + response.statusCode() + " when asked who you are");
        }
        ConsoleAccount account;
        try {
            account = accountFrom(MAPPER.readTree(response.body()));
        } catch (ConsoleAccountException e) {
            throw e;
        } catch (Exception e) {
            throw new ConsoleAccountException(503, "AuthStack's answer could not be read");
        }
        if (cache.size() > 10_000) cache.clear();
        cache.put(key, new Cached(account, now.plus(CACHE)));
        return account;
    }

    /** The decision, given AuthStack's answer: platform administrators and organization administrators or viewers only. */
    static ConsoleAccount accountFrom(JsonNode me) {
        JsonNode user = me.path("user");
        String id = user.path("id").asText(null);
        if (id == null) throw new ConsoleAccountException(401, "AuthStack did not recognise this session");
        String email = user.hasNonNull("email") ? user.get("email").asText() : null;
        String organizationId = user.hasNonNull("organizationId") ? user.get("organizationId").asText() : null;
        Map<String, String> environments = new LinkedHashMap<>();
        for (JsonNode environment : me.path("environments")) {
            String envId = environment.path("id").asText(null);
            if (envId != null) environments.put(envId, environment.path("name").asText(envId));
        }
        String role = user.path("role").asText("");
        return switch (role) {
            case "ADMIN" -> new ConsoleAccount(id, email, ConsoleAccount.Role.ADMIN, organizationId, environments);
            case "ORG_ADMIN", "ORG_VIEWER" -> {
                if (organizationId == null) throw new ConsoleAccountException(403, "This account belongs to no organization");
                yield new ConsoleAccount(id, email, ConsoleAccount.Role.valueOf(role), organizationId, environments);
            }
            default -> throw new ConsoleAccountException(403,
                    (email != null ? email : "This account") + " may not administer credential issuance or verification");
        };
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
