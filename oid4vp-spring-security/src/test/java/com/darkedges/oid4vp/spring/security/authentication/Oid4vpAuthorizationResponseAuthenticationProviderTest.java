package com.darkedges.oid4vp.spring.security.authentication;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.darkedges.oid4vp.spring.security.web.InMemoryOid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestContext;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationResponseAuthenticationConverter;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.darkedges.oid4vp.verifier.AuthorizationResponseValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Full simulated {@code direct_post}: a form-encoded POST carrying the real
 * {@code sd_jwt_vcld/01/sd_jwt_presentation.txt} fixture as {@code vp_token}, run through the
 * converter + {@link Oid4vpAuthorizationResponseAuthenticationProvider}, asserting the resulting
 * {@link SecurityContext} holds an authenticated {@link Oid4vpAuthenticationToken} whose principal
 * exposes the disclosed {@code givenName} claim.
 */
class Oid4vpAuthorizationResponseAuthenticationProviderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String VCT = "https://credentials.example.com/example_credential";
    private static final String REGISTRATION_ID = "demo-verifier";

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

    private static Oid4vpAuthorizationResponseAuthenticationProvider provider() throws Exception {
        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.DC_SD_JWT, new SdJwtVerifier()));
        return new Oid4vpAuthorizationResponseAuthenticationProvider(validator, issuerKeyResolver(), fixedClock());
    }

    private static DcqlQuery dcqlQuery() {
        CredentialQuery credentialQuery = CredentialQuery.builder("my_credential", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of(VCT)))
                .build();
        return DcqlQuery.of(List.of(credentialQuery));
    }

    @Test
    void authenticatesAFullDirectPostRequestAndExposesTheDisclosedClaim() throws Exception {
        Oid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        String state = "test-state-1";
        // A pre-registered client id equal to the bare verifier identifier, so fullClientId() (the
        // expected KB-JWT audience) matches the fixture's KB-JWT "aud" claim exactly (no prefix).
        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                REGISTRATION_ID, state, keyBindingNonce(),
                new ClientIdentifierPrefix.PreRegistered(verifierIdentifier()),
                dcqlQuery(), URI.create("https://verifier.example.org/oid4vp/response"),
                Instant.now().plusSeconds(300)));

        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/oid4vp/direct-post/" + REGISTRATION_ID);
        request.addParameter("state", state);
        request.addParameter("vp_token", "{\"my_credential\":[\"" + presentation + "\"]}");

        Oid4vpAuthorizationResponseAuthenticationConverter converter =
                new Oid4vpAuthorizationResponseAuthenticationConverter(requestRepository);
        Authentication unauthenticated = converter.convert(request);

        Authentication authenticated = provider().authenticate(unauthenticated);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authenticated);
        SecurityContextHolder.setContext(context);
        try {
            Authentication fromHolder = SecurityContextHolder.getContext().getAuthentication();
            assertThat(fromHolder).isInstanceOf(Oid4vpAuthenticationToken.class);
            assertThat(fromHolder.isAuthenticated()).isTrue();

            Oid4vpPrincipal principal = (Oid4vpPrincipal) fromHolder.getPrincipal();
            assertThat(principal.claim("my_credential", "ld", "credentialSubject", "givenName"))
                    .hasValueSatisfying(node -> assertThat(node.asText()).isEqualTo("John"));
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void rejectsWhenStateIsUnknown() {
        Oid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login/oid4vp/direct-post/" + REGISTRATION_ID);
        request.addParameter("state", "never-issued");
        request.addParameter("vp_token", "{}");

        Oid4vpAuthorizationResponseAuthenticationConverter converter =
                new Oid4vpAuthorizationResponseAuthenticationConverter(requestRepository);

        assertThatThrownBy(() -> converter.convert(request)).isInstanceOf(AuthenticationException.class);
    }
}
