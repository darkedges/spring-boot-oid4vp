package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The demo verifier on the "tenancy" profile, over real HTTP: two path tenants with a relying party of the same name, and the default
 * tenant (irving) as the verifier was. Each asks for presentations as itself, and none accepts a response to another's request.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("tenancy")
class MultiTenantDemoVerifierTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final String DCQL = "{\"credentials\":[{\"id\":\"employee\",\"format\":\"dc+sd-jwt\","
            + "\"meta\":{\"vct_values\":[\"https://vct.example/employee\"]},\"claims\":[{\"path\":[\"given_name\"]}]}]}";

    @LocalServerPort
    int port;

    @Autowired
    TenantRepository tenants;

    @Autowired
    Oid4vpAuthorizationRequestRepository requests;

    @Autowired
    ECKey demoVerifierSigningKey;

    @BeforeEach
    void tenants() throws Exception {
        ObjectNode settings = (ObjectNode) MAPPER.readTree(
                "{\"registrations\":{\"demo\":{\"dcqlQuery\":" + DCQL + ",\"walletAuthorizationEndpoint\":\"openid4vp://authorize\"}}}");
        if (tenants.findBySlug("bank").isEmpty()) tenants.save(Tenant.create("env-bank", "org-1", "bank").withSettings(settings));
        if (tenants.findBySlug("shop").isEmpty()) tenants.save(Tenant.create("env-shop", "org-2", "shop").withSettings(settings));
    }

    private String origin() {
        return "http://localhost:" + port;
    }

    private HttpResponse<String> get(String path) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(origin() + path)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postForm(String path, String body) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(origin() + path)).header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private JsonNode authorize(String prefix) throws Exception {
        HttpResponse<String> response = get(prefix + "/oid4vp/authorize/demo");
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return MAPPER.readTree(response.body());
    }

    private static String hash(SignedJWT jwt) throws Exception {
        byte[] der = Base64.getDecoder().decode(jwt.getHeader().getX509CertChain().get(0).toString());
        return Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(der)).toString();
    }

    @Test
    void eachTenantAsksAsItselfOnItsOwnUrls() throws Exception {
        JsonNode bank = authorize("/t/bank");
        JsonNode shop = authorize("/t/shop");
        assertThat(bank.path("response_uri").asText()).isEqualTo(origin() + "/t/bank/login/oid4vp/direct-post/demo");
        assertThat(bank.path("client_id").asText()).startsWith("x509_hash:");
        assertThat(shop.path("client_id").asText()).isNotEqualTo(bank.path("client_id").asText());

        // The bank's signed request: signed by the key whose certificate its client id names.
        SignedJWT requestObject = SignedJWT.parse(get("/t/bank/oid4vp/request/demo").body());
        assertThat("x509_hash:" + hash(requestObject)).isEqualTo(bank.path("client_id").asText());
        assertThat(requestObject.getJWTClaimsSet().getStringClaim("response_uri")).isEqualTo(origin() + "/t/bank/login/oid4vp/direct-post/demo");

        // Wallet invocation points at the tenant's own request_uri.
        HttpResponse<String> invoke = get("/t/bank/oid4vp/invoke/demo");
        assertThat(invoke.statusCode()).isEqualTo(302);
        String location = URLDecoder.decode(invoke.headers().firstValue("Location").orElseThrow(), StandardCharsets.UTF_8);
        assertThat(location).startsWith("openid4vp://authorize?").contains("request_uri=" + origin() + "/t/bank/oid4vp/request/demo");

        // The demo page's configuration points the wallet at the tenant.
        assertThat(MAPPER.readTree(get("/t/bank/demo-config").body()).path("verifierAuthorizeUrlForWallet").asText())
                .isEqualTo(origin() + "/t/bank/oid4vp/authorize/demo");
    }

    @Test
    void aResponseToOneTenantsRequestIsRefusedByAnotherAndLeftForItsOwn() throws Exception {
        String state = authorize("/t/bank").path("state").asText();
        HttpResponse<String> atShop = postForm("/t/shop/login/oid4vp/direct-post/demo", "state=" + state + "&vp_token=%7B%7D");
        assertThat(atShop.statusCode()).as("refused: unknown state at the shop").isEqualTo(400);
        // Not burnt by the attempt: the bank's request is still waiting for its genuine response.
        assertThat(requests.consume(state, "env-bank/demo")).isPresent();
    }

    @Test
    void theDefaultTenantIsTheVerifierAsItWas() throws Exception {
        JsonNode irving = authorize("");
        assertThat(irving.path("client_id").asText()).isEqualTo("x509_hash:Q8xBESl73Ce97aSLsk8TP7zWKEoEsYS5uuBFjjWyhK8");
        SignedJWT requestObject = SignedJWT.parse(get("/oid4vp/request/demo").body());
        assertThat(requestObject.verify(new ECDSAVerifier(demoVerifierSigningKey.toPublicJWK()))).isTrue();
        // A tenant's request object is not signed with the application's key.
        assertThat(SignedJWT.parse(get("/t/bank/oid4vp/request/demo").body()).verify(new ECDSAVerifier(demoVerifierSigningKey.toPublicJWK()))).isFalse();
    }

    @Test
    void unknownTenantsAndRelyingPartiesAreNotFound() throws Exception {
        assertThat(get("/t/nobody/oid4vp/authorize/demo").statusCode()).isEqualTo(404);
        assertThat(get("/t/bank/oid4vp/authorize/nobody").statusCode()).isEqualTo(404);
        // irving's own relying parties aren't the bank's.
        assertThat(get("/t/bank/oid4vp/authorize/demomdoc").statusCode()).isEqualTo(404);
    }
}
