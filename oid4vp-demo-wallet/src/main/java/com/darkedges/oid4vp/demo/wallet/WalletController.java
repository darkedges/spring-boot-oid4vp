package com.darkedges.oid4vp.demo.wallet;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQueryReader;
import com.darkedges.oid4vp.core.dcql.eval.CredentialStore;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.darkedges.oid4vp.core.request.ClientMetadata;
import com.darkedges.oid4vp.core.request.ClientMetadataReader;
import com.darkedges.oid4vp.core.response.VpToken;
import com.darkedges.oid4vp.core.response.VpTokenWriter;
import com.darkedges.oid4vp.wallet.HolderKeyResolver;
import com.darkedges.oid4vp.wallet.MdocPresentationBuilderAdapter;
import com.darkedges.oid4vp.wallet.PresentationBuildParams;
import com.darkedges.oid4vp.wallet.PresentationBuilder;
import com.darkedges.oid4vp.wallet.ResponseEncryptor;
import com.darkedges.oid4vp.wallet.SdJwtVcPresentationBuilderAdapter;
import com.darkedges.oid4vp.wallet.WalletAuthorizationResponseBuilder;
import com.darkedges.oid4vp.wallet.WalletAuthorizationResponseResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;

/**
 * The demo Wallet's only two endpoints: publish the self-issued credential's issuer key (so a Verifier
 * can resolve it), and, on request, fetch an Authorization Request from a Verifier, evaluate it against
 * the local credential store, and POST the resulting {@code vp_token} to the Verifier's
 * {@code response_uri} — the same {@link WalletAuthorizationResponseBuilder} orchestration a real Wallet
 * would use, just triggered over HTTP instead of from a UI. For a {@code direct_post.jwt} registration,
 * encrypts the response instead of posting it in the clear.
 */
@RestController
public class WalletController {

    private static final Logger log = LoggerFactory.getLogger(WalletController.class);

    private final ECKey issuerKey;
    private final ECKey holderKey;
    private final KeyPair mdocDeviceKeyPair;
    private final CredentialStore credentialStore;
    private final RestClient restClient = RestClient.create();
    private final ObjectMapper mapper = new ObjectMapper();

    public WalletController(
            ECKey demoIssuerKey, ECKey demoHolderKey, KeyPair demoMdocDeviceKeyPair, CredentialStore demoCredentialStore) {
        this.issuerKey = demoIssuerKey;
        this.holderKey = demoHolderKey;
        this.mdocDeviceKeyPair = demoMdocDeviceKeyPair;
        this.credentialStore = demoCredentialStore;
    }

    @GetMapping(value = "/issuer-jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> issuerJwks() {
        return new JWKSet(issuerKey.toPublicJWK()).toJSONObject();
    }

    // Allows the browser demo page, served by the Verifier on its own origin, to call this endpoint
    // directly via fetch() rather than needing a server-side proxy.
    @CrossOrigin(origins = "${demo.verifier-origin:http://localhost:8090}")
    @PostMapping(value = "/present", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> present(@RequestBody PresentRequest body) throws Exception {
        log.info("Fetching Authorization Request from {}", body.verifierAuthorizeUrl());
        String requestJson = restClient.get().uri(body.verifierAuthorizeUrl()).retrieve().body(String.class);
        JsonNode request = mapper.readTree(requestJson);

        // A real Wallet would derive this itself from the signed Request Object's x5c chain when the
        // client_id is x509_san_dns (OpenID4VP requires binding to "x509_hash:<sha256 of the leaf cert>",
        // not the literal client_id) — this endpoint's unsigned request never carries that certificate, so
        // AuthorizeController precomputes the value for us instead. See its Javadoc for why that's safe
        // only because this whole flow is a demo-only convenience shortcut.
        JsonNode expectedAudience = request.get("expected_response_audience");
        String audience = expectedAudience != null && !expectedAudience.isNull()
                ? expectedAudience.asText() : request.get("client_id").asText();
        String clientId = request.get("client_id").asText();
        String nonce = request.get("nonce").asText();
        String state = request.get("state").asText();
        String responseUri = request.get("response_uri").asText();
        DcqlQuery dcqlQuery = DcqlQueryReader.read(request.get("dcql_query"));

        String responseMode = request.hasNonNull("response_mode") ? request.get("response_mode").asText() : "direct_post";
        boolean encryptedResponse = responseMode.endsWith(".jwt");
        ClientMetadata clientMetadata = encryptedResponse ? ClientMetadataReader.read(request.get("client_metadata")) : null;
        Optional<JsonNode> responseEncryptionPublicJwk = encryptedResponse
                ? Optional.of(resolveResponseEncryptionPublicJwk(clientMetadata))
                : Optional.empty();

        WalletAuthorizationResponseBuilder builder = new WalletAuthorizationResponseBuilder(Map.of(
                CredentialFormat.DC_SD_JWT, (PresentationBuilder) new SdJwtVcPresentationBuilderAdapter(),
                CredentialFormat.MSO_MDOC, new MdocPresentationBuilderAdapter()));
        HolderKeyResolver holderKeyResolver = new HolderKeyResolver() {
            @Override
            public Optional<com.nimbusds.jose.JWSSigner> resolveSigner(HeldCredential credential) {
                try {
                    return Optional.of(new ECDSASigner(holderKey));
                } catch (com.nimbusds.jose.JOSEException e) {
                    throw new IllegalStateException(e);
                }
            }

            @Override
            public Optional<PrivateKey> resolvePrivateKey(HeldCredential credential) {
                return Optional.of(mdocDeviceKeyPair.getPrivate());
            }
        };

        WalletAuthorizationResponseResult result = builder.build(
                dcqlQuery, credentialStore,
                new PresentationBuildParams(
                        nonce, audience, clientId, responseUri, responseEncryptionPublicJwk, holderKeyResolver, Clock.systemUTC()));

        if (result instanceof WalletAuthorizationResponseResult.Declined declined) {
            log.warn("Declining: {}", declined.reason());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("{\"error\":\"access_denied\",\"reason\":\"" + declined.reason() + "\"}");
        }

        VpToken vpToken = ((WalletAuthorizationResponseResult.Built) result).vpToken();
        String vpTokenJson = mapper.writeValueAsString(VpTokenWriter.write(vpToken));
        log.info("Posting vp_token to {}", responseUri);

        String formBody = encryptedResponse
                ? "response=" + URLEncoder.encode(buildEncryptedResponse(clientMetadata, vpTokenJson, state), StandardCharsets.UTF_8)
                : "vp_token=" + URLEncoder.encode(vpTokenJson, StandardCharsets.UTF_8)
                        + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);

        String verifierResponse = restClient.post()
                .uri(responseUri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formBody)
                .retrieve()
                .body(String.class);

        log.info("Verifier responded: {}", verifierResponse);
        return ResponseEntity.ok(verifierResponse);
    }

    private String buildEncryptedResponse(ClientMetadata clientMetadata, String vpTokenJson, String state) throws Exception {
        JsonNode jwks = clientMetadata.jwks()
                .orElseThrow(() -> new IllegalStateException("direct_post.jwt requires client_metadata.jwks"));

        ObjectNode payload = mapper.createObjectNode();
        payload.set("vp_token", mapper.readTree(vpTokenJson));
        payload.put("state", state);

        return ResponseEncryptor.encrypt(payload, jwks, clientMetadata.encryptedResponseEncValuesSupportedOrDefault());
    }

    private JsonNode resolveResponseEncryptionPublicJwk(ClientMetadata clientMetadata) {
        JsonNode jwks = clientMetadata.jwks()
                .orElseThrow(() -> new IllegalStateException("direct_post.jwt requires client_metadata.jwks"));
        JsonNode keys = jwks.get("keys");
        if (keys == null || !keys.isArray() || keys.isEmpty()) {
            throw new IllegalStateException("client_metadata.jwks has no keys");
        }
        return keys.get(0);
    }

    public record PresentRequest(String verifierAuthorizeUrl) {}
}
