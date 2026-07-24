package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.response.ResponseDecryptionKeyResolver;
import com.darkedges.oid4vp.spring.security.web.Oid4vpEphemeralEncryptionKeyRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Instant;
import java.util.Optional;

/**
 * Decrypts {@code direct_post.jwt} responses (used only by the {@code conformance} relying-party
 * registration — see {@code application-cloudflare.yml}) using whichever response-encryption private keys
 * {@link Oid4vpEphemeralEncryptionKeyRepository} currently has live for that registration.
 *
 * <p>There is no static key here: HAIP forbids reusing the same response-encryption public key across
 * Authorization Requests, so {@code Oid4vpAuthorizationRequestService} generates a fresh keypair per
 * request and saves the private half into this repository — this bean just reads it back out. It's the
 * <em>same</em> repository instance {@code SecurityConfig} wires into {@code Oid4vpLoginConfigurer} via
 * {@code .ephemeralEncryptionKeyRepository(...)}; Spring supplies the identical singleton bean to both,
 * but if this were ever split into two separately-constructed instances, decryption would always fail
 * with "no key found" since nothing would ever be saved into the copy this bean reads from.
 */
@Configuration
public class DemoVerifierEncryptionKeyConfig {

    @Bean
    public ResponseDecryptionKeyResolver responseDecryptionKeyResolver(
            Oid4vpEphemeralEncryptionKeyRepository ephemeralEncryptionKeyRepository) {
        return registrationId -> Optional.of(ephemeralEncryptionKeyRepository.resolveLiveKeys(registrationId, Instant.now()));
    }
}
