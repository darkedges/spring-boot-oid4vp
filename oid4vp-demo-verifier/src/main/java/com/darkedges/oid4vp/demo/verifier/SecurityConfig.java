package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.darkedges.oid4vp.core.request.TokenEndpointClient;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.PresentationVerifier;
import com.darkedges.oid4vp.core.response.ResponseDecryptionKeyResolver;
import com.darkedges.oid4vp.spring.security.config.Oid4vpLoginConfigurer;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.web.InMemoryOid4vpTransactionResultRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpEphemeralEncryptionKeyRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpTransactionResultRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Wires {@link Oid4vpLoginConfigurer} into the security filter chain: {@code /oid4vp/**} (the authorize
 * and same-device result endpoints) and {@code /login/oid4vp/**} (the direct_post/dc_api response
 * endpoints, per the library's default path patterns) are open to the Wallet; everything else requires a
 * validated presentation. The issuer key is resolved first from the credential's own embedded
 * {@code x5c} certificate chain (self-signed, no CA validation — demo-only), falling back to fetching
 * the demo Wallet's own {@code /issuer-jwks} endpoint for credentials that carry no {@code x5c} (only
 * our own demo Wallet's self-issued credential). Real deployments would use actual Issuer trust
 * configuration instead.
 */
@Configuration
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public Oid4vpTransactionResultRepository transactionResultRepository() {
        return new InMemoryOid4vpTransactionResultRepository();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            Oid4vpRelyingPartyRegistrationRepository registrations,
            Oid4vpAuthorizationRequestRepository requestRepository,
            Oid4vpEphemeralEncryptionKeyRepository ephemeralEncryptionKeyRepository,
            Oid4vpTransactionResultRepository transactionResultRepository,
            @Qualifier("sdJwtVcPresentationVerifier") PresentationVerifier sdJwtVcPresentationVerifier,
            IssuerKeyResolver issuerKeyResolver,
            RequestObjectSigningKeyResolver requestObjectSigningKeyResolver,
            ResponseDecryptionKeyResolver responseDecryptionKeyResolver,
            TokenEndpointClient tokenEndpointClient,
            @Value("${demo.same-device-result-base-uri:http://localhost:8090/oid4vp/result}") String sameDeviceResultBaseUri,
            @Value("${demo.request-uri-base:http://localhost:8090/oid4vp/request}") String requestUriBase)
            throws Exception {

        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/index.html", "/demo-config", "/oid4vp/**", "/login/oid4vp/**").permitAll()
                        .anyRequest().authenticated())
                .with(Oid4vpLoginConfigurer.oid4vpLogin(), configurer -> configurer
                        .relyingPartyRegistrationRepository(registrations)
                        .authorizationRequestRepository(requestRepository)
                        // Must be the same instance DemoVerifierEncryptionKeyConfig's responseDecryptionKeyResolver
                        // reads from — see Oid4vpLoginConfigurer.ephemeralEncryptionKeyRepository's Javadoc.
                        .ephemeralEncryptionKeyRepository(ephemeralEncryptionKeyRepository)
                        .presentationVerifier(sdJwtVcPresentationVerifier)
                        .issuerKeyResolver(issuerKeyResolver)
                        .requestObjectSigningKeyResolver(requestObjectSigningKeyResolver)
                        .requestObjectSigningAlgorithm(JWSAlgorithm.ES256)
                        // Only the "conformance" registration actually uses direct_post.jwt — see
                        // application-cloudflare.yml and DemoVerifierEncryptionKeyConfig.
                        .responseDecryptionKeyResolver(responseDecryptionKeyResolver)
                        .sameDeviceHandoff(transactionResultRepository, sameDeviceResultBaseUri)
                        .sameDeviceResultRedirectUri("/")
                        .walletInvocation(requestUriBase)
                        // Only the "conformancecode" registration actually uses response_type=code — see
                        // application-cloudflare.yml.
                        .authorizationCodeCallback(tokenEndpointClient)
                        .authorizationCodeSuccessRedirectUri("/"));

        return http.build();
    }

    /** Plain PKCE authorization_code token exchange (RFC 6749 §4.1.3 + RFC 7636) — POSTs form-encoded to
     * whichever registration's {@code CodeFlowConfig.tokenEndpoint()} the caller supplies. */
    @Bean
    public TokenEndpointClient tokenEndpointClient() {
        RestClient restClient = RestClient.create();
        return (tokenEndpoint, code, redirectUri, clientId, codeVerifier) -> {
            String formBody = "grant_type=authorization_code"
                    + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                    + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                    + "&code_verifier=" + URLEncoder.encode(codeVerifier, StandardCharsets.UTF_8);
            return restClient.post()
                    .uri(tokenEndpoint)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(formBody)
                    .retrieve()
                    .body(JsonNode.class);
        };
    }

    @Bean
    public IssuerKeyResolver issuerKeyResolver(@Value("${demo.wallet-base-url}") String walletBaseUrl) {
        RestClient restClient = RestClient.create();
        ObjectMapper mapper = new ObjectMapper();
        String jwksUri = walletBaseUrl + "/issuer-jwks";
        return (issuer, keyId, certificateChain) -> {
            if (!certificateChain.isEmpty()) {
                Optional<JsonNode> fromCertificateChain = resolveFromCertificateChain(certificateChain, mapper);
                if (fromCertificateChain.isPresent()) {
                    return fromCertificateChain;
                }
            }
            try {
                String body = restClient.get().uri(jwksUri).retrieve().body(String.class);
                JsonNode jwks = mapper.readTree(body);
                JsonNode keys = jwks.get("keys");
                if (keys == null || keys.isEmpty()) {
                    return Optional.empty();
                }
                return Optional.of(keys.get(0));
            } catch (Exception e) {
                log.warn("Failed to fetch issuer JWKS from {}: {}", jwksUri, e.toString());
                return Optional.empty();
            }
        };
    }

    /**
     * Extracts the issuer's public key straight from the leaf certificate of a credential's own
     * {@code x5c} chain — no chain-of-trust/CA validation, demo-only (same self-signed, no-real-PKI
     * pattern as {@link DemoVerifierSigningKeyConfig}). This lets the Verifier accept credentials from
     * any Wallet whose issuer self-signs its key, not just our own demo Wallet.
     */
    private static Optional<JsonNode> resolveFromCertificateChain(List<String> certificateChain, ObjectMapper mapper) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            byte[] leafCertDer = Base64.getDecoder().decode(certificateChain.get(0));
            X509Certificate leafCert = (X509Certificate)
                    certificateFactory.generateCertificate(new ByteArrayInputStream(leafCertDer));
            ECPublicKey publicKey = (ECPublicKey) leafCert.getPublicKey();
            ECKey jwk = new ECKey.Builder(Curve.P_256, publicKey).build();
            return Optional.of(mapper.readTree(jwk.toJSONString()));
        } catch (Exception e) {
            log.warn("Failed to extract issuer key from x5c certificate chain: {}", e.toString());
            return Optional.empty();
        }
    }
}
