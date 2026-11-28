package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.tenantapi.TenantCallers;
import com.darkedges.oid4vp.sdjwt.KbJwtBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.ActiveProfiles;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A tenant's backend asking for a presentation, over real HTTP: it creates a transaction, a wallet fetches the request and answers it
 * with a real SD-JWT presentation, and the backend collects the result once.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("tenancy")
class TenantTransactionApiTest {

    /** Each tenant's backend has its own token; the check against AuthStack is covered in oid4vc-tenancy. */
    @TestConfiguration
    static class Callers {
        @Bean
        TenantCallers tenantCallers() {
            return (token, tenant) -> {
                if (token == null || !token.startsWith("backend-of-")) throw new TenantCallers.TenantCallerException(401, "no token");
                if (!token.equals("backend-of-" + tenant.id())) throw new TenantCallers.TenantCallerException(403, "another tenant's");
                return new TenantCallers.TenantCaller(tenant.id(), "backend");
            };
        }
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final String ISSUER = "https://issuer.test";
    private static final String VCT = "https://issuer.test/vct/Employee";
    private static final String BANK = "backend-of-env-bank";
    private static final String SHOP = "backend-of-env-shop";
    private static final ECKey ISSUER_KEY = key();
    private static final ECKey HOLDER_KEY = key();

    @LocalServerPort
    int port;

    @Autowired
    TenantRepository tenants;

    private static ECKey key() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @BeforeEach
    void tenants() throws Exception {
        ObjectNode settings = (ObjectNode) MAPPER.readTree("""
                {"registrations":{"staff":{"requestParameters":["not_before_check"],
                   "dcqlQuery":{"credentials":[{"id":"staff","format":"dc+sd-jwt","meta":{"vct_values":["%s"]},
                                               "claims":[{"path":["given_name"]}]}]}}},
                 "trustedIssuers":[{"issuer":"%s","jwks":{"keys":[%s]}}]}
                """.formatted(VCT, ISSUER, ISSUER_KEY.toPublicJWK().toJSONString()));
        if (tenants.findBySlug("bank").isEmpty()) tenants.save(Tenant.create("env-bank", "org-1", "bank").withSettings(settings));
        if (tenants.findBySlug("shop").isEmpty()) tenants.save(Tenant.create("env-shop", "org-2", "shop").withSettings(settings));
    }

    private String origin() {
        return "http://localhost:" + port;
    }

    private HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> api(String method, String path, String token, String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(origin() + path)).header("Content-Type", "application/json")
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (token != null) request.header("Authorization", "Bearer " + token);
        return send(request);
    }

    private HttpResponse<String> create(String body) throws Exception {
        return api("POST", "/t/bank/tenant-api/v1/transactions", BANK, body);
    }

    private String status(String transactionId) throws Exception {
        HttpResponse<String> response = api("GET", "/t/bank/tenant-api/v1/transactions/" + transactionId, BANK, null);
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return MAPPER.readTree(response.body()).path("status").asText();
    }

    /** What the wallet reads at the request_uri. */
    private JWTClaimsSet fetch(String requestUri) throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder(URI.create(requestUri)).GET());
        assertThat(response.statusCode()).isEqualTo(200);
        return SignedJWT.parse(response.body()).getJWTClaimsSet();
    }

    private static String presentation(JWTClaimsSet request, ECKey issuerKey, String vct) throws Exception {
        SignedJWT credential = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dc+sd-jwt")).keyID("k1").build(),
                new JWTClaimsSet.Builder().issuer(ISSUER).claim("vct", vct).claim("given_name", "Jane")
                        .claim("cnf", Map.of("jwk", HOLDER_KEY.toPublicJWK().toJSONObject()))
                        .expirationTime(Date.from(Instant.now().plusSeconds(600))).build());
        credential.sign(new ECDSASigner(issuerKey));
        String sdJwt = credential.serialize() + "~";
        SignedJWT binding = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("kb+jwt")).build(),
                new JWTClaimsSet.Builder().audience(request.getStringClaim("client_id")).claim("nonce", request.getStringClaim("nonce"))
                        .issueTime(new Date()).claim("sd_hash", KbJwtBuilder.computeSdHash(sdJwt, "sha-256")).build());
        binding.sign(new ECDSASigner(HOLDER_KEY));
        return sdJwt + binding.serialize();
    }

    private HttpResponse<String> respond(JWTClaimsSet request, String field, String value) throws Exception {
        String body = "state=" + request.getStringClaim("state") + "&" + field + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8);
        return send(HttpRequest.newBuilder(URI.create(request.getStringClaim("response_uri")))
                .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(body)));
    }

    private HttpResponse<String> answer(JWTClaimsSet request, String presentation) throws Exception {
        return respond(request, "vp_token", "{\"staff\":[\"" + presentation + "\"]}");
    }

    @Test
    void theBackendAsksTheWalletAnswersAndTheBackendCollectsTheResultOnce() throws Exception {
        HttpResponse<String> created = create("{\"registrationId\":\"staff\",\"reference\":\"hire-7\",\"expiresIn\":120,"
                + "\"requestParameters\":{\"not_before_check\":\"2026-01-01T00:00:00Z\"}}");
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        assertThat(created.headers().firstValue("Cache-Control")).hasValue("no-store");
        JsonNode transaction = MAPPER.readTree(created.body());
        String id = transaction.path("transactionId").asText();
        String requestUri = transaction.path("requestUri").asText();
        assertThat(requestUri).startsWith(origin() + "/t/bank/oid4vp/transaction-request/").doesNotContain(id);
        assertThat(URLDecoder.decode(transaction.path("walletUri").asText(), StandardCharsets.UTF_8))
                .startsWith("openid4vp://?client_id=x509_hash:").endsWith("&request_uri=" + requestUri);
        assertThat(status(id)).isEqualTo("pending");

        JWTClaimsSet first = fetch(requestUri);
        assertThat(first.getStringClaim("response_uri")).isEqualTo(origin() + "/t/bank/login/oid4vp/direct-post/staff");
        assertThat(first.getStringClaim("not_before_check")).isEqualTo("2026-01-01T00:00:00Z");
        assertThat(first.getStringClaim("expires_at")).isNotBlank();

        // Nothing but a presentation that verifies answers it: not another type, not an untrusted signature, not a wallet's error.
        assertThat(answer(first, presentation(first, ISSUER_KEY, "https://issuer.test/vct/Visitor")).statusCode()).isEqualTo(400);
        JWTClaimsSet second = fetch(requestUri);
        assertThat(answer(second, presentation(second, key(), VCT)).statusCode()).isEqualTo(400);
        assertThat(respond(fetch(requestUri), "error", "access_denied").statusCode()).isEqualTo(400);
        assertThat(status(id)).isEqualTo("pending");
        assertThat(api("POST", "/t/bank/tenant-api/v1/transactions/" + id + "/consume", BANK, null).statusCode()).isEqualTo(409);

        JWTClaimsSet genuine = fetch(requestUri);
        JWTClaimsSet other = fetch(requestUri);
        HttpResponse<String> accepted = answer(genuine, presentation(genuine, ISSUER_KEY, VCT));
        assertThat(accepted.statusCode()).as(accepted.body()).isEqualTo(200);
        assertThat(accepted.body()).as("no browser is sent anywhere").isEqualTo("{}");

        // Answered once: not by a second request fetched earlier, and nothing more is served.
        assertThat(answer(other, presentation(other, ISSUER_KEY, VCT)).statusCode()).isEqualTo(400);
        assertThat(send(HttpRequest.newBuilder(URI.create(requestUri)).GET()).statusCode()).isEqualTo(404);
        assertThat(status(id)).isEqualTo("verified");

        // Another tenant neither sees it nor collects it.
        assertThat(api("GET", "/t/shop/tenant-api/v1/transactions/" + id, SHOP, null).statusCode()).isEqualTo(404);
        assertThat(api("POST", "/t/shop/tenant-api/v1/transactions/" + id + "/consume", SHOP, null).statusCode()).isEqualTo(404);
        assertThat(api("POST", "/t/bank/tenant-api/v1/transactions/" + id + "/consume", SHOP, null).statusCode()).isEqualTo(403);

        HttpResponse<String> collected = api("POST", "/t/bank/tenant-api/v1/transactions/" + id + "/consume", BANK, null);
        assertThat(collected.statusCode()).as(collected.body()).isEqualTo(200);
        JsonNode result = MAPPER.readTree(collected.body());
        assertThat(result.path("reference").asText()).isEqualTo("hire-7");
        JsonNode staff = result.path("credentials").path("staff");
        assertThat(staff.path("format").asText()).isEqualTo("dc+sd-jwt");
        assertThat(staff.path("issuer").asText()).isEqualTo(ISSUER);
        assertThat(staff.path("claims").path("given_name").asText()).isEqualTo("Jane");
        assertThat(staff.path("claims").path("vct").asText()).isEqualTo(VCT);
        assertThat(staff.path("holderKey").path("x").asText()).isEqualTo(HOLDER_KEY.getX().toString());

        assertThat(api("POST", "/t/bank/tenant-api/v1/transactions/" + id + "/consume", BANK, null).statusCode()).isEqualTo(409);
        assertThat(status(id)).isEqualTo("collected");
    }

    @Test
    void onlyTheTenantsBackendMayAsk() throws Exception {
        String body = "{\"registrationId\":\"staff\"}";
        assertThat(api("POST", "/t/bank/tenant-api/v1/transactions", null, body).statusCode()).isEqualTo(401);
        assertThat(api("POST", "/t/bank/tenant-api/v1/transactions", SHOP, body).statusCode()).isEqualTo(403);
        assertThat(api("GET", "/t/bank/tenant-api/v1/transactions/anything", null, null).statusCode()).isEqualTo(401);
        assertThat(api("POST", "/t/nobody/tenant-api/v1/transactions", BANK, body).statusCode()).isEqualTo(404);
    }

    @Test
    void refusesWhatTheRegistrationDoesNotAllow() throws Exception {
        for (String body : new String[] {
                "not json",
                "{}",
                "{\"registrationId\":\"nobody\"}",
                "{\"registrationId\":\"a/b\"}",
                "{\"registrationId\":\"staff\",\"requestParameters\":{\"unlisted\":\"x\"}}",
                "{\"registrationId\":\"staff\",\"requestParameters\":{\"nonce\":\"chosen\"}}",
                "{\"registrationId\":\"staff\",\"requestParameters\":{\"expires_at\":\"2099-01-01T00:00:00Z\"}}",
                "{\"registrationId\":\"staff\",\"requestParameters\":{\"not_before_check\":7}}",
                "{\"registrationId\":\"staff\",\"requestParameters\":{\"not_before_check\":\"" + "x".repeat(257) + "\"}}",
                "{\"registrationId\":\"staff\",\"expiresIn\":30}",
                "{\"registrationId\":\"staff\",\"expiresIn\":3600}",
                "{\"registrationId\":\"staff\",\"reference\":\"has spaces\"}"}) {
            assertThat(create(body).statusCode()).as(body).isEqualTo(400);
        }
    }

    @Test
    void aRequestThatSignsABrowserInStillSendsItBack() throws Exception {
        SignedJWT hosted = SignedJWT.parse(send(HttpRequest.newBuilder(URI.create(origin() + "/t/bank/oid4vp/request/staff")).GET()).body());
        JWTClaimsSet request = hosted.getJWTClaimsSet();
        HttpResponse<String> accepted = answer(request, presentation(request, ISSUER_KEY, VCT));
        assertThat(accepted.statusCode()).as(accepted.body()).isEqualTo(200);
        assertThat(MAPPER.readTree(accepted.body()).path("redirect_uri").asText()).contains("/t/bank/oid4vp/result/");
    }
}
