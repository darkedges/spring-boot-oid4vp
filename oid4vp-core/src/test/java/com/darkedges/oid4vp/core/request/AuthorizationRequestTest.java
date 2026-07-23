package com.darkedges.oid4vp.core.request;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Validation for the {@code response_type=code} (Authorization Code Grant) shape: {@code QUERY}
 * response mode requires {@code redirect_uri} and forbids {@code response_uri} — the inverse of the
 * existing {@code direct_post} rule. */
class AuthorizationRequestTest {

    private static DcqlQuery sampleDcqlQuery() {
        return DcqlQuery.of(List.of(CredentialQuery.builder("pid", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://credentials.example.com/identity_credential")))
                .build()));
    }

    @Test
    void queryResponseModeRequiresRedirectUriAndForbidsResponseUri() {
        assertThatThrownBy(() -> new AuthorizationRequest(
                "code",
                new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                ResponseMode.QUERY,
                Optional.empty(),
                Optional.empty(), // no redirect_uri
                Optional.of(sampleDcqlQuery()),
                Optional.empty(),
                Optional.of("some-state"),
                "some-nonce",
                Optional.empty(),
                RequestUriMethod.GET,
                List.of(),
                List.of(),
                Optional.of("challenge"),
                Optional.of("S256")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("redirect_uri is required");

        assertThatThrownBy(() -> new AuthorizationRequest(
                "code",
                new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                ResponseMode.QUERY,
                Optional.of("https://verifier.example.org/response"), // response_uri present too — not allowed
                Optional.of("https://verifier.example.org/callback"),
                Optional.of(sampleDcqlQuery()),
                Optional.empty(),
                Optional.of("some-state"),
                "some-nonce",
                Optional.empty(),
                RequestUriMethod.GET,
                List.of(),
                List.of(),
                Optional.of("challenge"),
                Optional.of("S256")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("response_uri MUST NOT be present");
    }

    @Test
    void queryResponseModeWithRedirectUriAndNoResponseUriIsValid() {
        AuthorizationRequest request = new AuthorizationRequest(
                "code",
                new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                ResponseMode.QUERY,
                Optional.empty(),
                Optional.of("https://verifier.example.org/callback"),
                Optional.of(sampleDcqlQuery()),
                Optional.empty(),
                Optional.of("some-state"),
                "some-nonce",
                Optional.empty(),
                RequestUriMethod.GET,
                List.of(),
                List.of(),
                Optional.of("challenge-value"),
                Optional.of("S256"));

        assertThat(request.responseUri()).isEmpty();
        assertThat(request.redirectUri()).contains("https://verifier.example.org/callback");
        assertThat(request.codeChallenge()).contains("challenge-value");
        assertThat(request.codeChallengeMethod()).contains("S256");
    }

    @Test
    void writerSerializesRedirectUriAndCodeChallengeFields() {
        AuthorizationRequest request = new AuthorizationRequest(
                "code",
                new ClientIdentifierPrefix.X509SanDns("verifier.example.org"),
                ResponseMode.QUERY,
                Optional.empty(),
                Optional.of("https://verifier.example.org/callback"),
                Optional.of(sampleDcqlQuery()),
                Optional.empty(),
                Optional.of("some-state"),
                "some-nonce",
                Optional.empty(),
                RequestUriMethod.GET,
                List.of(),
                List.of(),
                Optional.of("challenge-value"),
                Optional.of("S256"));

        var json = AuthorizationRequestWriter.write(request);

        assertThat(json.get("response_type").asText()).isEqualTo("code");
        assertThat(json.get("response_mode").asText()).isEqualTo("query");
        assertThat(json.get("redirect_uri").asText()).isEqualTo("https://verifier.example.org/callback");
        assertThat(json.has("response_uri")).isFalse();
        assertThat(json.get("code_challenge").asText()).isEqualTo("challenge-value");
        assertThat(json.get("code_challenge_method").asText()).isEqualTo("S256");
    }

    @Test
    void codeChallengeFieldsAreOmittedFromTheWireFormatWhenAbsent() {
        AuthorizationRequest request = new AuthorizationRequest(
                "vp_token",
                new ClientIdentifierPrefix.RedirectUri("https://verifier.example.org/response"),
                ResponseMode.DIRECT_POST,
                Optional.of("https://verifier.example.org/response"),
                Optional.empty(),
                Optional.of(sampleDcqlQuery()),
                Optional.empty(),
                Optional.of("some-state"),
                "some-nonce",
                Optional.empty(),
                RequestUriMethod.GET,
                List.of(),
                List.of(),
                Optional.empty(),
                Optional.empty());

        var json = AuthorizationRequestWriter.write(request);

        assertThat(json.has("code_challenge")).isFalse();
        assertThat(json.has("code_challenge_method")).isFalse();
    }
}
