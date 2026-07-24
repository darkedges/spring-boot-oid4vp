package com.darkedges.oid4vp.spring.boot.autoconfigure;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.response.PresentationVerifier;
import com.darkedges.oid4vp.jwtvcjson.JwtVcJsonVerifier;
import com.darkedges.oid4vp.mdoc.MdocVerifier;
import com.darkedges.oid4vp.sdjwt.SdJwtVerifier;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/** Exercises {@link Oid4vpVerifierAutoConfiguration} with a representative {@code oid4vp.verifier.*}
 * property set, using a Spring Boot {@link ApplicationContextRunner} rather than a full application. */
class Oid4vpVerifierAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(Oid4vpVerifierAutoConfiguration.class))
            .withPropertyValues(
                    "oid4vp.verifier.relying-party.demo.client-id=redirect_uri:https://verifier.example.org/oid4vp/response",
                    "oid4vp.verifier.relying-party.demo.response-uri=https://verifier.example.org/oid4vp/response",
                    "oid4vp.verifier.relying-party.demo.dcql-query={\"credentials\":[{\"id\":\"pid\",\"format\":\"dc+sd-jwt\","
                            + "\"meta\":{\"vct_values\":[\"https://credentials.example.com/identity_credential\"]}}]}");

    @Test
    void wiresUpDefaultBeansFromProperties() {
        contextRunner.run((AssertableApplicationContext context) -> {
            assertThat(context).hasSingleBean(Oid4vpAuthorizationRequestRepository.class);
            assertThat(context).hasSingleBean(Oid4vpRelyingPartyRegistrationRepository.class);
            assertThat(context).hasSingleBean(Oid4vpAuthorizationRequestService.class);
            assertThat(context).hasBean("sdJwtVcPresentationVerifier");
            assertThat(context.getBean("sdJwtVcPresentationVerifier", PresentationVerifier.class))
                    .isInstanceOf(SdJwtVerifier.class);
            assertThat(context).hasBean("jwtVcJsonPresentationVerifier");
            assertThat(context.getBean("jwtVcJsonPresentationVerifier", PresentationVerifier.class))
                    .isInstanceOf(JwtVcJsonVerifier.class);
            assertThat(context).hasBean("mdocPresentationVerifier");
            assertThat(context.getBean("mdocPresentationVerifier", PresentationVerifier.class))
                    .isInstanceOf(MdocVerifier.class);
            assertThat(context.getBeanProvider(PresentationVerifier.class).stream().map(PresentationVerifier::format))
                    .containsExactlyInAnyOrder(CredentialFormat.DC_SD_JWT, CredentialFormat.JWT_VC_JSON, CredentialFormat.MSO_MDOC);

            Oid4vpRelyingPartyRegistrationRepository registrations = context.getBean(Oid4vpRelyingPartyRegistrationRepository.class);
            Oid4vpRelyingPartyRegistration demo = registrations.findByRegistrationId("demo").orElseThrow();
            assertThat(demo.clientId()).isEqualTo(
                    new ClientIdentifierPrefix.RedirectUri("https://verifier.example.org/oid4vp/response"));
            assertThat(demo.dcqlQuery().get().findCredential("pid")).isPresent();
        });
    }

    @Test
    void backsOffWhenUserSuppliesTheirOwnRequestRepository() {
        contextRunner.withUserConfiguration(CustomRequestRepositoryConfiguration.class).run(context -> {
            assertThat(context).hasSingleBean(Oid4vpAuthorizationRequestRepository.class);
            assertThat(context.getBean(Oid4vpAuthorizationRequestRepository.class))
                    .isSameAs(CustomRequestRepositoryConfiguration.INSTANCE);
        });
    }

    @org.springframework.context.annotation.Configuration(proxyBeanMethods = false)
    static class CustomRequestRepositoryConfiguration {
        static final Oid4vpAuthorizationRequestRepository INSTANCE =
                new com.darkedges.oid4vp.spring.security.web.InMemoryOid4vpAuthorizationRequestRepository();

        @org.springframework.context.annotation.Bean
        Oid4vpAuthorizationRequestRepository customRepository() {
            return INSTANCE;
        }
    }
}
