package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.spring.security.registration.Oid4vpRegistrationKey;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Which tenant a request is for. A single-tenant verifier has one ({@link #SINGLE_TENANT}); a multi-tenant one resolves it from the
 * request's host or path ({@code oid4vc-tenancy}). Combined with the registration id in the path, it gives the
 * {@linkplain Oid4vpRegistrationKey registration key} everything is looked up by.
 */
@FunctionalInterface
public interface Oid4vpTenantResolver {

    String tenantId(HttpServletRequest request);

    Oid4vpTenantResolver SINGLE_TENANT = request -> Oid4vpRegistrationKey.DEFAULT_TENANT;

    /** The registration key for the registration this request names by {@code registrationId}. */
    default String registrationKey(HttpServletRequest request, String registrationId) {
        return Oid4vpRegistrationKey.of(tenantId(request), registrationId);
    }
}
