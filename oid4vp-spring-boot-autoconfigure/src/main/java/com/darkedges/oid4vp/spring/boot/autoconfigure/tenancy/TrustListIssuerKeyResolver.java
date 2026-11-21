package com.darkedges.oid4vp.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A tenant's trusted credential issuers, from its {@code settings.trustedIssuers}:
 * <pre>
 * "trustedIssuers": [
 *   { "issuer": "https://issuer.zkp.au/t/bank", "jwksUri": "https://issuer.zkp.au/t/bank/jwks" },
 *   { "issuer": "https://issuer.bank.example",  "jwks": { "keys": [ ... ] } },
 *   { "issuer": "https://issuer.zkp.au",        "x5cTrustAnchors": [ "-----BEGIN CERTIFICATE-----..." ] }
 * ]
 * </pre>
 * A presentation's issuer must be listed. Its key is the listed JWKS key with the credential's {@code kid} (or the only one), or
 * the leaf of its {@code x5c} when that leaf was issued by a listed trust anchor and is valid now. An issuer not on the list yields
 * no key, so the presentation is refused. A {@code jwksUri} is fetched at most once every five minutes.
 */
public final class TrustListIssuerKeyResolver implements IssuerKeyResolver {

    private static final Logger log = LoggerFactory.getLogger(TrustListIssuerKeyResolver.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration JWKS_CACHE = Duration.ofMinutes(5);

    /** One trusted issuer. */
    public record TrustedIssuer(String issuer, Optional<JWKSet> jwks, Optional<URI> jwksUri, List<X509Certificate> trustAnchors) {}

    private record Fetched(JWKSet set, Instant at) {}

    private final List<TrustedIssuer> issuers;
    private final HttpClient http;
    private final Clock clock;
    private final Map<URI, Fetched> fetched = new ConcurrentHashMap<>();

    public TrustListIssuerKeyResolver(List<TrustedIssuer> issuers, HttpClient http, Clock clock) {
        this.issuers = List.copyOf(issuers);
        this.http = http;
        this.clock = clock;
    }

    @Override
    public Optional<JsonNode> resolve(String issuer, Optional<String> keyId, List<String> certificateChain) {
        for (TrustedIssuer trusted : issuers) {
            if (!trusted.issuer().equals(issuer)) continue;
            Optional<JWK> key = fromChain(trusted, certificateChain)
                    .or(() -> trusted.jwks().flatMap(set -> select(set, keyId)))
                    .or(() -> trusted.jwksUri().flatMap(uri -> fetch(uri)).flatMap(set -> select(set, keyId)));
            if (key.isPresent()) return Optional.of(json(key.get().toPublicJWK()));
        }
        return Optional.empty();
    }

    private Optional<JWK> fromChain(TrustedIssuer trusted, List<String> certificateChain) {
        if (trusted.trustAnchors().isEmpty() || certificateChain == null || certificateChain.isEmpty()) return Optional.empty();
        try {
            X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(certificateChain.get(0))));
            leaf.checkValidity(java.util.Date.from(clock.instant()));
            for (X509Certificate anchor : trusted.trustAnchors()) {
                try {
                    if (!leaf.getIssuerX500Principal().equals(anchor.getSubjectX500Principal())) continue;
                    leaf.verify(anchor.getPublicKey());
                    return Optional.of(ECKey.parse(leaf));
                } catch (Exception notThisAnchor) {
                    // try the next anchor
                }
            }
        } catch (Exception e) {
            log.debug("x5c leaf of {} not usable: {}", trusted.issuer(), e.toString());
        }
        return Optional.empty();
    }

    private static Optional<JWK> select(JWKSet set, Optional<String> keyId) {
        if (keyId.isPresent()) return Optional.ofNullable(set.getKeyByKeyId(keyId.get()));
        return set.getKeys().size() == 1 ? Optional.of(set.getKeys().get(0)) : Optional.empty();
    }

    private Optional<JWKSet> fetch(URI uri) {
        Instant now = clock.instant();
        Fetched cached = fetched.get(uri);
        if (cached != null && now.isBefore(cached.at().plus(JWKS_CACHE))) return Optional.of(cached.set());
        try {
            HttpResponse<String> response = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) throw new IllegalStateException("HTTP " + response.statusCode());
            JWKSet set = JWKSet.parse(response.body());
            fetched.put(uri, new Fetched(set, now));
            return Optional.of(set);
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            log.warn("Could not fetch trusted issuer JWKS {}: {}", uri, e.toString());
            return cached == null ? Optional.empty() : Optional.of(cached.set());
        }
    }

    private static JsonNode json(JWK key) {
        try {
            return MAPPER.readTree(key.toJSONString());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Reads {@code settings.trustedIssuers}. */
    public static List<TrustedIssuer> read(JsonNode trustedIssuers) {
        List<TrustedIssuer> result = new ArrayList<>();
        if (trustedIssuers == null || !trustedIssuers.isArray()) return result;
        for (JsonNode entry : trustedIssuers) {
            String issuer = entry.path("issuer").asText("");
            if (issuer.isBlank()) throw new IllegalArgumentException("a trusted issuer needs \"issuer\"");
            Optional<JWKSet> jwks = Optional.empty();
            if (entry.hasNonNull("jwks")) {
                try {
                    JWKSet set = JWKSet.parse(entry.get("jwks").toString());
                    if (set.getKeys().stream().anyMatch(JWK::isPrivate)) throw new IllegalArgumentException("trusted keys must be public: " + issuer);
                    jwks = Optional.of(set);
                } catch (java.text.ParseException e) {
                    throw new IllegalArgumentException("unreadable \"jwks\" for " + issuer);
                }
            }
            Optional<URI> jwksUri = Optional.empty();
            if (entry.hasNonNull("jwksUri")) {
                URI uri = URI.create(entry.get("jwksUri").asText());
                if (!"https".equals(uri.getScheme()) && !"localhost".equals(uri.getHost())) {
                    throw new IllegalArgumentException("\"jwksUri\" must be https: " + issuer);
                }
                jwksUri = Optional.of(uri);
            }
            List<X509Certificate> anchors = new ArrayList<>();
            for (JsonNode pem : entry.path("x5cTrustAnchors")) anchors.add(certificate(pem.asText(), issuer));
            if (jwks.isEmpty() && jwksUri.isEmpty() && anchors.isEmpty()) {
                throw new IllegalArgumentException("trusted issuer " + issuer + " needs \"jwks\", \"jwksUri\" or \"x5cTrustAnchors\"");
            }
            result.add(new TrustedIssuer(issuer, jwks, jwksUri, List.copyOf(anchors)));
        }
        return result;
    }

    private static X509Certificate certificate(String pem, String issuer) {
        try {
            String body = pem.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "").replaceAll("\\s", "");
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(body)));
        } catch (Exception e) {
            throw new IllegalArgumentException("unreadable trust anchor for " + issuer);
        }
    }
}
