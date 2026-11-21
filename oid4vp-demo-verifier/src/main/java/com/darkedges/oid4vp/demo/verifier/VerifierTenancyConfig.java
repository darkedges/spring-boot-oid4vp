package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.spring.boot.autoconfigure.Oid4vpProperties;
import com.darkedges.oid4vp.spring.boot.autoconfigure.tenancy.Oid4vpTenancy;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestService;
import com.darkedges.oid4vp.spring.security.web.Oid4vpEphemeralEncryptionKeyRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * The Authorization Request service behind {@code /oid4vp/authorize/{registrationId}}: over every tenant's registrations with the
 * "tenancy" profile ({@link Oid4vpTenancy}), over this application's own otherwise. It replaces the auto-configured one, which knows
 * only the application's.
 */
@Configuration
public class VerifierTenancyConfig {

    @Bean
    public Oid4vpAuthorizationRequestService oid4vpAuthorizationRequestService(
            Oid4vpRelyingPartyRegistrationRepository registrations, Oid4vpAuthorizationRequestRepository requests,
            Oid4vpEphemeralEncryptionKeyRepository ephemeralKeys, Oid4vpProperties properties, ObjectProvider<Oid4vpTenancy> tenancy) {
        Oid4vpTenancy t = tenancy.getIfAvailable();
        return new Oid4vpAuthorizationRequestService(t == null ? registrations : t.registrations(registrations), requests, ephemeralKeys,
                Clock.systemUTC(), properties.getRequestTtl());
    }
}
