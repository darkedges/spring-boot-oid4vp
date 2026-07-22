package com.darkedges.oid4vp.spring.security.registration;

import java.util.Optional;

/** Mirrors Spring Security's {@code ClientRegistrationRepository} for OpenID4VP relying-party
 * registrations. */
public interface Oid4vpRelyingPartyRegistrationRepository {

    Optional<Oid4vpRelyingPartyRegistration> findByRegistrationId(String registrationId);
}
