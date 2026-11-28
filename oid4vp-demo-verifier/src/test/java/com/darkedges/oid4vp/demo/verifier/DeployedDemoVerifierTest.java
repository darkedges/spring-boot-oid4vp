package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The demo as deployed (the "cloudflare" profile): its own signing key, and only the issuers it lists. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("cloudflare")
class DeployedDemoVerifierTest {

    private static final String PASSWORD = "only-for-this-test";
    private static final Path KEYSTORE = generate();

    @DynamicPropertySource
    static void ownKey(DynamicPropertyRegistry registry) {
        registry.add("demo.signing.keystore", KEYSTORE::toString);
        registry.add("demo.signing.keystore-password", () -> PASSWORD);
    }

    @LocalServerPort
    int port;

    @Autowired
    ECKey demoVerifierSigningKey;

    @Autowired
    IssuerKeyResolver issuerKeyResolver;

    /** A new key, made as an operator would make one. */
    private static Path generate() {
        try {
            Path file = Files.createTempDirectory("verifier-key").resolve("verifier.p12");
            String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
            List<String> command = new ArrayList<>(List.of(keytool, "-genkeypair", "-alias", "demo-verifier-signing", "-keyalg", "EC",
                    "-groupname", "secp256r1", "-dname", "CN=own verifier", "-validity", "2", "-storetype", "PKCS12",
                    "-keystore", file.toString(), "-storepass", PASSWORD));
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            String output = new String(process.getInputStream().readAllBytes());
            if (process.waitFor() != 0) throw new IllegalStateException(output);
            return file;
        } catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    private SignedJWT request(String registration) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/oid4vp/request/" + registration)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return SignedJWT.parse(response.body());
    }

    @Test
    void asksAsItsOwnKeyWithoutAnyValueBeingReconfigured() throws Exception {
        SignedJWT request = request("demo");
        assertThat(request.verify(new ECDSAVerifier(demoVerifierSigningKey.toPublicJWK()))).isTrue();
        assertThat(request.verify(new ECDSAVerifier(DemoVerifierSigningKeyConfig.published().toPublicJWK()))).isFalse();
        String hash = Base64URL.encode(MessageDigest.getInstance("SHA-256")
                .digest(request.getHeader().getX509CertChain().get(0).decode())).toString();
        assertThat(request.getJWTClaimsSet().getStringClaim("client_id")).isEqualTo("x509_hash:" + hash);
        var info = new ObjectMapper().valueToTree(request.getJWTClaimsSet().getClaim("verifier_info"));
        assertThat(JWSObject.parse(info.get(0).get("data").asText()).verify(new ECDSAVerifier(demoVerifierSigningKey.toPublicJWK()))).isTrue();
    }

    @Test
    void doesNotTrustAnIssuerForBringingItsOwnCertificate() {
        List<String> chain = List.of(demoVerifierSigningKey.getX509CertChain().get(0).toString());
        assertThat(issuerKeyResolver.resolve("https://stranger.example", Optional.empty(), chain)).isEmpty();
        assertThat(issuerKeyResolver.resolve("https://issuer.zkp.au.stranger.example", Optional.of("k"), chain)).isEmpty();
    }

    @Test
    void willNotRunWithThePublishedKeyOrNone() {
        var config = new DemoVerifierSigningKeyConfig();
        var environment = new MockEnvironment().withProperty("demo.signing.require-external-key", "true");
        assertThatThrownBy(() -> config.demoVerifierSigningKey(environment)).hasMessageContaining("needs its own request signing key");
        environment.setProperty("demo.signing.keystore", "src/main/resources/demo-verifier-signing-key.p12");
        environment.setProperty("demo.signing.keystore-password", "changeit");
        assertThatThrownBy(() -> config.demoVerifierSigningKey(environment)).hasMessageContaining("which is public");
        environment.setProperty("demo.signing.keystore", "no-such-file.p12");
        assertThatThrownBy(() -> config.demoVerifierSigningKey(environment)).hasMessageContaining("Cannot read");
    }
}
