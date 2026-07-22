package com.darkedges.oid4vp.spring.security.registration;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class InMemoryOid4vpRelyingPartyRegistrationRepository implements Oid4vpRelyingPartyRegistrationRepository {

    private final Map<String, Oid4vpRelyingPartyRegistration> byRegistrationId;

    public InMemoryOid4vpRelyingPartyRegistrationRepository(List<Oid4vpRelyingPartyRegistration> registrations) {
        Map<String, Oid4vpRelyingPartyRegistration> map = new LinkedHashMap<>();
        for (Oid4vpRelyingPartyRegistration registration : registrations) {
            map.put(registration.registrationId(), registration);
        }
        this.byRegistrationId = Map.copyOf(map);
    }

    public InMemoryOid4vpRelyingPartyRegistrationRepository(Oid4vpRelyingPartyRegistration... registrations) {
        this(List.of(registrations));
    }

    @Override
    public Optional<Oid4vpRelyingPartyRegistration> findByRegistrationId(String registrationId) {
        return Optional.ofNullable(byRegistrationId.get(registrationId));
    }
}
