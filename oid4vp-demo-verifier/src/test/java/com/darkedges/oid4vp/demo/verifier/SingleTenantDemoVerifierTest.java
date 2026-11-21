package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** Without the "tenancy" profile the demo verifier is single-tenant, exactly as before, on any host. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SingleTenantDemoVerifierTest {

    @LocalServerPort
    int port;

    @Autowired
    ObjectProvider<TenantRepository> tenants;

    @Test
    void servesItsOwnRelyingPartiesWithNoTenancy() throws Exception {
        assertThat(tenants.getIfAvailable()).isNull();
        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + port + "/oid4vp/authorize/demo")).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(new ObjectMapper().readTree(response.body()).path("client_id").asText())
                .isEqualTo("x509_hash:Q8xBESl73Ce97aSLsk8TP7zWKEoEsYS5uuBFjjWyhK8");
    }
}
