package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationProvider;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.darkedges.oid4vp.verifier.AuthorizationResponseValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end {@code direct_post.jwt}: encrypts a real Authorization Response payload (containing the
 * {@code sd_jwt_vcld/01} presentation fixture) to a freshly generated Verifier response-decryption key,
 * submits it as the {@code response} form field, and confirms the converter decrypts it, resolves the
 * request context by the {@code state} carried <em>inside</em> the encrypted payload, and that the
 * resulting token authenticates successfully.
 */
class Oid4vpAuthorizationResponseAuthenticationConverterEncryptedTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String REGISTRATION_ID = "demo-verifier";
    private static final String VCT = "https://credentials.example.com/example_credential";
    private static final RequestMatcher REQUEST_MATCHER =
            PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login/oid4vp/direct-post/{registrationId}");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> sdJwtVcldSettings() {
        return FixtureLoader.readYaml("examples/sd_jwt_vcld/settings.yml");
    }

    private static String verifierIdentifier() {
        return ((Map<String, Object>) sdJwtVcldSettings().get("identifiers")).get("verifier").toString();
    }

    private static String keyBindingNonce() {
        return sdJwtVcldSettings().get("key_binding_nonce").toString();
    }

    @SuppressWarnings("unchecked")
    private static IssuerKeyResolver issuerKeyResolver() throws Exception {
        Map<String, Object> keySettings = (Map<String, Object>) sdJwtVcldSettings().get("key_settings");
        Map<String, Object> issuerKeyYaml = ((List<Map<String, Object>>) keySettings.get("issuer_keys")).get(0);
        ECKey issuerKey = new ECKey.Builder(Curve.P_256,
                new Base64URL(issuerKeyYaml.get("x").toString()),
                new Base64URL(issuerKeyYaml.get("y").toString()))
                .build();
        JsonNode jwk = MAPPER.readTree(issuerKey.toJSONString());
        return (issuer, keyId) -> Optional.of(jwk);
    }

    private static Clock fixedClock() {
        return Clock.fixed(Instant.ofEpochSecond(1744743394L), ZoneOffset.UTC);
    }

    @Test
    void decryptsAndAuthenticatesAnEncryptedDirectPostResponse() throws Exception {
        // The Verifier's own response-decryption key pair for this registration.
        ECKey encryptionKey = new ECKeyGenerator(Curve.P_256).keyID("verifier-enc-1").generate();
        // toJSONObject(false): publicKeysOnly=false, i.e. include the private key material needed to decrypt.
        JsonNode privateJwks = MAPPER.valueToTree(new JWKSet(encryptionKey).toJSONObject(false));

        String state = "encrypted-state-1";
        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, keyBindingNonce(),
                new ClientIdentifierPrefix.PreRegistered(verifierIdentifier()),
                DcqlQuery.of(List.of(CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                        .meta(new SdJwtVcMeta(List.of(VCT)))
                        .build())),
                java.net.URI.create("https://verifier.example.org/oid4vp/response"),
                Instant.now().plusSeconds(300)));

        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("state", state);
        ObjectNode vpToken = payload.putObject("vp_token");
        vpToken.putArray("my_credential").add(presentation);

        String encryptedResponse = encrypt(payload, encryptionKey);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/oid4vp/direct-post/" + REGISTRATION_ID);
        request.addParameter("response", encryptedResponse);

        Oid4vpAuthorizationResponseAuthenticationConverter converter = new Oid4vpAuthorizationResponseAuthenticationConverter(
                requestRepository, REQUEST_MATCHER, registrationId -> Optional.of(privateJwks));

        Authentication unauthenticated = converter.convert(request);

        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));
        Oid4vpAuthorizationResponseAuthenticationProvider provider =
                new Oid4vpAuthorizationResponseAuthenticationProvider(validator, issuerKeyResolver(), fixedClock());

        Authentication authenticated = provider.authenticate(unauthenticated);

        assertThat(authenticated).isInstanceOf(Oid4vpAuthenticationToken.class);
        Oid4vpPrincipal principal = (Oid4vpPrincipal) authenticated.getPrincipal();
        assertThat(principal.claim("my_credential", "ld", "credentialSubject", "givenName"))
                .hasValueSatisfying(node -> assertThat(node.asText()).isEqualTo("John"));
    }

    private static String encrypt(JsonNode payload, ECKey publicKey) throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                .keyID(publicKey.getKeyID())
                .build();
        JWEObject jwe = new JWEObject(header, new Payload(payload.toString()));
        jwe.encrypt(new ECDHEncrypter(publicKey.toPublicJWK()));
        return jwe.serialize();
    }
}
