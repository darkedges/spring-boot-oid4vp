package com.darkedges.oid4vp.demo.verifier;

import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.VerifierInfoEntry;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.fasterxml.jackson.databind.node.TextNode;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.security.MessageDigest;
import java.util.List;

/**
 * Makes the configured registrations speak as whoever holds the signing key. With a key of your own ({@code demo.signing.keystore}),
 * each registration with an {@code x509_hash} client id gets that of the key's certificate, and its {@code jwt} {@code verifier_info}
 * is signed again with the key, so no value in the configuration has to be recomputed when the key changes. With the published demo
 * key the configuration stands as written.
 */
@Configuration
public class DemoVerifierIdentity {

    @Bean
    static BeanPostProcessor demoVerifierIdentityPostProcessor(Environment environment, ObjectProvider<ECKey> signingKey) {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (!(bean instanceof Oid4vpRelyingPartyRegistrationRepository registrations)
                        || environment.getProperty("demo.signing.keystore", "").isBlank()) {
                    return bean;
                }
                ECKey key = signingKey.getObject();
                return (Oid4vpRelyingPartyRegistrationRepository) id -> registrations.findByRegistrationId(id).map(r -> as(r, key));
            }
        };
    }

    static Oid4vpRelyingPartyRegistration as(Oid4vpRelyingPartyRegistration r, ECKey key) {
        if (!(r.clientId() instanceof ClientIdentifierPrefix.X509Hash)) return r;
        List<VerifierInfoEntry> info = r.verifierInfo().stream()
                .map(entry -> entry.format().equals("jwt") && entry.data().isTextual()
                        ? new VerifierInfoEntry(entry.format(), TextNode.valueOf(resign(entry.data().asText(), key)), entry.credentialIds())
                        : entry)
                .toList();
        return new Oid4vpRelyingPartyRegistration(r.registrationId(), new ClientIdentifierPrefix.X509Hash(certificateHash(key)),
                r.responseUri(), r.responseMode(), r.dcqlQuery(), r.clientMetadata(), r.walletAuthorizationEndpoint(), info,
                r.codeFlow(), r.requestUriMethod());
    }

    /** {@code x509_hash}: base64url SHA-256 of the DER certificate. */
    static String certificateHash(ECKey key) {
        try {
            return Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(key.getX509CertChain().get(0).decode())).toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String resign(String jwt, ECKey key) {
        try {
            JWSObject original = JWSObject.parse(jwt);
            JWSObject signed = new JWSObject(new JWSHeader.Builder(original.getHeader().getAlgorithm()).keyID(key.getKeyID()).build(),
                    original.getPayload());
            signed.sign(new ECDSASigner(key));
            return signed.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("could not sign the registration's verifier_info", e);
        }
    }
}
