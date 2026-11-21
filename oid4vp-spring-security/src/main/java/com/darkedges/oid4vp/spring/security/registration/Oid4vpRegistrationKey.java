package com.darkedges.oid4vp.spring.security.registration;

/**
 * The key a relying party registration is known by inside the verifier: {@code <tenant>/<registrationId>}, or just the
 * registration id for the {@linkplain #DEFAULT_TENANT default tenant}.
 *
 * <p>A request names a registration by its plain id ({@code /login/oid4vp/direct-post/{registrationId}}); the tenant comes from the
 * request (see {@link com.darkedges.oid4vp.spring.security.web.Oid4vpTenantResolver}). Everything looked up for a registration
 * (the registration itself, its stored request contexts, its request-signing and response-decryption keys, its ephemeral keys) is
 * looked up by this key. So a {@code state}, key or registration of one tenant is never found from another, and a single-tenant
 * verifier sees exactly the ids it always has.
 */
public final class Oid4vpRegistrationKey {

    public static final String DEFAULT_TENANT = "default";
    private static final char SEPARATOR = '/';

    private Oid4vpRegistrationKey() {}

    /**
     * @throws IllegalArgumentException for a blank id, or a tenant or id containing {@code /}
     */
    public static String of(String tenantId, String registrationId) {
        if (registrationId == null || registrationId.isBlank() || registrationId.indexOf(SEPARATOR) >= 0) {
            throw new IllegalArgumentException("not a registration id: " + registrationId);
        }
        if (tenantId == null || tenantId.isBlank() || DEFAULT_TENANT.equals(tenantId)) return registrationId;
        if (tenantId.indexOf(SEPARATOR) >= 0) throw new IllegalArgumentException("not a tenant id: " + tenantId);
        return tenantId + SEPARATOR + registrationId;
    }

    public static String tenantOf(String key) {
        int at = key.indexOf(SEPARATOR);
        return at < 0 ? DEFAULT_TENANT : key.substring(0, at);
    }

    public static String registrationIdOf(String key) {
        int at = key.indexOf(SEPARATOR);
        return at < 0 ? key : key.substring(at + 1);
    }
}
