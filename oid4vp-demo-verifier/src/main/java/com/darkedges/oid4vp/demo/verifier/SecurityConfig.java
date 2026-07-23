package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.PresentationVerifier;
import com.darkedges.oid4vp.core.response.ResponseDecryptionKeyResolver;
import com.darkedges.oid4vp.spring.security.config.Oid4vpLoginConfigurer;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.web.InMemoryOid4vpTransactionResultRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpTransactionResultRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestClient;

import java.util.Optional;

/**
 * Wires {@link Oid4vpLoginConfigurer} into the security filter chain: {@code /oid4vp/**} (the authorize
 * and same-device result endpoints) and {@code /login/oid4vp/**} (the direct_post/dc_api response
 * endpoints, per the library's default path patterns) are open to the Wallet; everything else requires a
 * validated presentation. The issuer key is resolved by fetching the demo Wallet's own
 * {@code /issuer-jwks} endpoint at verification time — real deployments would use actual Issuer trust
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
            Oid4vpTransactionResultRepository transactionResultRepository,
            @Qualifier("sdJwtVcPresentationVerifier") PresentationVerifier sdJwtVcPresentationVerifier,
            IssuerKeyResolver issuerKeyResolver,
            RequestObjectSigningKeyResolver requestObjectSigningKeyResolver,
            ResponseDecryptionKeyResolver responseDecryptionKeyResolver,
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
                        .presentationVerifier(sdJwtVcPresentationVerifier)
                        .issuerKeyResolver(issuerKeyResolver)
                        .requestObjectSigningKeyResolver(requestObjectSigningKeyResolver)
                        .requestObjectSigningAlgorithm(JWSAlgorithm.ES256)
                        // Only the "conformance" registration actually uses direct_post.jwt — see
                        // application-cloudflare.yml and DemoVerifierEncryptionKeyConfig.
                        .responseDecryptionKeyResolver(responseDecryptionKeyResolver)
                        .sameDeviceHandoff(transactionResultRepository, sameDeviceResultBaseUri)
                        .sameDeviceResultRedirectUri("/")
                        .walletInvocation(requestUriBase));

        return http.build();
    }

    @Bean
    public IssuerKeyResolver issuerKeyResolver(@Value("${demo.wallet-base-url}") String walletBaseUrl) {
        RestClient restClient = RestClient.create();
        ObjectMapper mapper = new ObjectMapper();
        String jwksUri = walletBaseUrl + "/issuer-jwks";
        return (issuer, keyId) -> {
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
}
