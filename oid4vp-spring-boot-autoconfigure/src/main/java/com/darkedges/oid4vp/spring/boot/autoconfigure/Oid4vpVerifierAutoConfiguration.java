package com.darkedges.oid4vp.spring.boot.autoconfigure;

import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQueryReader;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefixParser;
import com.darkedges.oid4vp.core.request.ClientMetadata;
import com.darkedges.oid4vp.core.request.ClientMetadataReader;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.core.response.PresentationVerifier;
import com.darkedges.oid4vp.jwtvcjson.JwtVcJsonVerifier;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.darkedges.oid4vp.spring.security.config.Oid4vpLoginConfigurer;
import com.darkedges.oid4vp.spring.security.registration.InMemoryOid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.web.InMemoryOid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Optional;

/**
 * Auto-configures the supporting beans for a Verifier using {@link Oid4vpLoginConfigurer}: in-memory
 * request/registration repositories built from {@code oid4vp.verifier.*} properties, and a default
 * {@code dc+sd-jwt} {@link PresentationVerifier}.
 *
 * <p>This does <em>not</em> auto-apply {@code Oid4vpLoginConfigurer} to any {@code HttpSecurity} — like
 * {@code oauth2Login()}, that's still applied explicitly in the application's own
 * {@code SecurityFilterChain @Bean} method, since Spring Security doesn't auto-wire DSL customizations.
 * An {@code IssuerKeyResolver} bean is deliberately not provided here — issuer trust configuration is
 * inherently deployment-specific.
 */
@AutoConfiguration
@EnableConfigurationProperties(Oid4vpProperties.class)
@ConditionalOnClass(Oid4vpLoginConfigurer.class)
public class Oid4vpVerifierAutoConfiguration {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Bean
    @ConditionalOnMissingBean
    public Oid4vpAuthorizationRequestRepository oid4vpAuthorizationRequestRepository() {
        return new InMemoryOid4vpAuthorizationRequestRepository();
    }

    @Bean
    @ConditionalOnMissingBean
    public Oid4vpRelyingPartyRegistrationRepository oid4vpRelyingPartyRegistrationRepository(Oid4vpProperties properties) {
        List<Oid4vpRelyingPartyRegistration> registrations = properties.getRelyingParty().entrySet().stream()
                .map(entry -> toRegistration(entry.getKey(), entry.getValue()))
                .toList();
        return new InMemoryOid4vpRelyingPartyRegistrationRepository(registrations);
    }

    @Bean(name = "sdJwtVcPresentationVerifier")
    @ConditionalOnMissingBean(name = "sdJwtVcPresentationVerifier")
    public PresentationVerifier sdJwtVcPresentationVerifier() {
        return new SdJwtVerifier();
    }

    @Bean(name = "jwtVcJsonPresentationVerifier")
    @ConditionalOnMissingBean(name = "jwtVcJsonPresentationVerifier")
    public PresentationVerifier jwtVcJsonPresentationVerifier() {
        return new JwtVcJsonVerifier();
    }

    @Bean
    @ConditionalOnMissingBean
    public Oid4vpAuthorizationRequestService oid4vpAuthorizationRequestService(
            Oid4vpRelyingPartyRegistrationRepository registrations,
            Oid4vpAuthorizationRequestRepository requestRepository,
            Oid4vpProperties properties) {
        return new Oid4vpAuthorizationRequestService(registrations, requestRepository, Clock.systemUTC(), properties.getRequestTtl());
    }

    private static Oid4vpRelyingPartyRegistration toRegistration(String registrationId, Oid4vpProperties.RelyingParty relyingParty) {
        ClientIdentifierPrefix clientId = ClientIdentifierPrefixParser.parse(relyingParty.getClientId());
        DcqlQuery dcqlQuery = readDcqlQuery(relyingParty.getDcqlQuery());
        ResponseMode responseMode = ResponseMode.fromValue(relyingParty.getResponseMode());
        Optional<ClientMetadata> clientMetadata = readClientMetadata(relyingParty.getClientMetadata());
        Optional<URI> walletAuthorizationEndpoint = Optional.ofNullable(relyingParty.getWalletAuthorizationEndpoint())
                .filter(value -> !value.isBlank())
                .map(URI::create);
        return new Oid4vpRelyingPartyRegistration(
                registrationId,
                clientId,
                URI.create(relyingParty.getResponseUri()),
                responseMode,
                () -> dcqlQuery,
                clientMetadata,
                walletAuthorizationEndpoint);
    }

    private static DcqlQuery readDcqlQuery(String json) {
        try {
            return DcqlQueryReader.read(MAPPER.readTree(json));
        } catch (Exception e) {
            throw new IllegalStateException("invalid oid4vp.verifier.relying-party.*.dcql-query JSON: " + json, e);
        }
    }

    private static Optional<ClientMetadata> readClientMetadata(String json) {
        if (json == null || json.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(ClientMetadataReader.read(MAPPER.readTree(json)));
        } catch (Exception e) {
            throw new IllegalStateException("invalid oid4vp.verifier.relying-party.*.client-metadata JSON: " + json, e);
        }
    }
}
