package com.darkedges.oid4vc.tenancy.tenantapi;

import com.darkedges.oid4vc.tenancy.Tenant;

/**
 * Who is calling a tenant API (a service's API for the tenant's own backend, such as creating offers or verifier transactions), and
 * whether they may. Unlike the admin API, which a person reaches through the AuthStack console, a tenant API is called machine to
 * machine, as the tenant, by an application of the tenant's own AuthStack environment.
 */
public interface TenantCallers {

    /**
     * The caller behind {@code bearerToken}, if it may act for {@code tenant}.
     *
     * @throws TenantCallerException 401 when the token is missing or not a valid token of the tenant's environment, 403 when it is valid
     *                               but its application isn't one the tenant allows
     */
    TenantCaller verify(String bearerToken, Tenant tenant);

    /** An application of the tenant's environment, acting for the tenant. */
    record TenantCaller(String tenantId, String clientId) {}

    /** Why a call was refused, with the HTTP status to answer. */
    final class TenantCallerException extends RuntimeException {
        private final int status;

        public TenantCallerException(int status, String message) {
            super(message);
            this.status = status;
        }

        public int status() { return status; }

        /** {@code invalid_token} or {@code insufficient_scope} (RFC 6750). */
        public String error() { return status == 401 ? "invalid_token" : "insufficient_scope"; }
    }
}
