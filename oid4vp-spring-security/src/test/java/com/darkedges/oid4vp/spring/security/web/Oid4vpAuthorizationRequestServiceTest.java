package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.AuthorizationRequest;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.ClientMetadata;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.spring.security.registration.CodeFlowConfig;
import com.darkedges.oid4vp.spring.security.registration.InMemoryOid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class Oid4vpAuthorizationRequestServiceTest {

    private static DcqlQuery sampleDcqlQuery() {
        return DcqlQuery.of(List.of(CredentialQuery.builder("employee", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://demo.oid4vp.example/employee_credential")))
                .build()));
    }

    @Test
    void codeFlowRegistrationProducesACodeRequestWithAMatchingPkceChallenge() throws Exception {
        DcqlQuery dcqlQuery = sampleDcqlQuery();
        Oid4vpRelyingPartyRegistration registration = new Oid4vpRelyingPartyRegistration(
                "conformancecode",
                new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                URI.create("https://verifier.example.org/unused-response-uri"),
                ResponseMode.DIRECT_POST, // must be ignored/overridden by codeFlow's presence
                () -> dcqlQuery,
                Optional.empty(),
                Optional.empty(),
                List.of(),
                Optional.of(new CodeFlowConfig(
                        URI.create("https://verifier.example.org/callback"),
                        Optional.of(URI.create("https://wallet.example.com/token")))));

        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        Oid4vpAuthorizationRequestService service = new Oid4vpAuthorizationRequestService(
                new InMemoryOid4vpRelyingPartyRegistrationRepository(registration), requestRepository,
                new InMemoryOid4vpEphemeralEncryptionKeyRepository(), Clock.systemUTC(), Duration.ofMinutes(10));

        AuthorizationRequest request = service.resolve("conformancecode").request();

        assertThat(request.responseType()).isEqualTo("code");
        assertThat(request.responseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(request.redirectUri()).contains("https://verifier.example.org/callback");
        assertThat(request.responseUri()).isEmpty();
        assertThat(request.codeChallengeMethod()).contains("S256");
        assertThat(request.codeChallenge()).isPresent();

        String state = request.state().orElseThrow();
        Oid4vpAuthorizationRequestContext context = requestRepository.consume(state).orElseThrow();
        String codeVerifier = context.codeVerifier().orElseThrow();

        // Independently re-derive S256(code_verifier) and confirm it matches the advertised code_challenge.
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        String expectedChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        assertThat(request.codeChallenge()).contains(expectedChallenge);
    }

    @Test
    void registrationWithoutCodeFlowIsUnaffected() {
        DcqlQuery dcqlQuery = sampleDcqlQuery();
        Oid4vpRelyingPartyRegistration registration = new Oid4vpRelyingPartyRegistration(
                "demo",
                new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                URI.create("https://verifier.example.org/response"),
                ResponseMode.DIRECT_POST,
                () -> dcqlQuery,
                Optional.empty(),
                Optional.empty(),
                List.of(),
                Optional.empty());

        InMemoryOid4vpAuthorizationRequestRepository requestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
        Oid4vpAuthorizationRequestService service = new Oid4vpAuthorizationRequestService(
                new InMemoryOid4vpRelyingPartyRegistrationRepository(registration), requestRepository,
                new InMemoryOid4vpEphemeralEncryptionKeyRepository(), Clock.systemUTC(), Duration.ofMinutes(10));

        AuthorizationRequest request = service.resolve("demo").request();

        assertThat(request.responseType()).isEqualTo("vp_token");
        assertThat(request.responseMode()).isEqualTo(ResponseMode.DIRECT_POST);
        assertThat(request.responseUri()).contains("https://verifier.example.org/response");
        assertThat(request.redirectUri()).isEmpty();
        assertThat(request.codeChallenge()).isEmpty();
        assertThat(request.codeChallengeMethod()).isEmpty();

        String state = request.state().orElseThrow();
        Oid4vpAuthorizationRequestContext context = requestRepository.consume(state).orElseThrow();
        assertThat(context.codeVerifier()).isEmpty();
        assertThat(request.clientMetadata()).isEmpty();
    }

    @Test
    void directPostJwtRegistrationGetsAFreshResponseEncryptionKeyPerRequest() {
        DcqlQuery dcqlQuery = sampleDcqlQuery();
        ClientMetadata staticMetadata = new ClientMetadata(Optional.empty(), List.of("A128GCM"), Map.of());
        Oid4vpRelyingPartyRegistration registration = new Oid4vpRelyingPartyRegistration(
                "conformance",
                new ClientIdentifierPrefix.X509Hash("dummy-hash"),
                URI.create("https://verifier.example.org/response"),
                ResponseMode.DIRECT_POST_JWT,
                () -> dcqlQuery,
                Optional.of(staticMetadata),
                Optional.empty(),
                List.of(),
                Optional.empty());

        InMemoryOid4vpEphemeralEncryptionKeyRepository ephemeralKeys = new InMemoryOid4vpEphemeralEncryptionKeyRepository();
        Oid4vpAuthorizationRequestService service = new Oid4vpAuthorizationRequestService(
                new InMemoryOid4vpRelyingPartyRegistrationRepository(registration), new InMemoryOid4vpAuthorizationRequestRepository(),
                ephemeralKeys, Clock.systemUTC(), Duration.ofMinutes(10));

        AuthorizationRequest first = service.resolve("conformance").request();
        AuthorizationRequest second = service.resolve("conformance").request();

        String firstKid = publicKeyId(first);
        String secondKid = publicKeyId(second);
        assertThat(firstKid).isNotEqualTo(secondKid);

        // encrypted_response_enc_values_supported/vp_formats_supported carried through from the static
        // config unchanged; only jwks was replaced.
        assertThat(first.clientMetadata()).isPresent();
        assertThat(first.clientMetadata().get().encryptedResponseEncValuesSupported()).isEqualTo(List.of("A128GCM"));

        // Both generated keys are still independently resolvable (neither overwrote the other).
        JsonNode liveKeys = ephemeralKeys.resolveLiveKeys("conformance", Instant.now());
        List<String> liveKids = new ArrayList<>();
        liveKeys.get("keys").forEach(k -> liveKids.add(k.get("kid").asText()));
        assertThat(liveKids).containsExactlyInAnyOrder(firstKid, secondKid);
    }

    private static String publicKeyId(AuthorizationRequest request) {
        JsonNode jwks = request.clientMetadata().orElseThrow().jwks().orElseThrow();
        return jwks.get("keys").get(0).get("kid").asText();
    }
}
