package com.darkedges.oid4vp.spring.security.authentication;

import com.darkedges.oid4vp.core.response.IssuerKeyResolver;

/**
 * Which credential issuers each tenant trusts: the {@link IssuerKeyResolver} its presentations are verified with. A tenant's trust
 * list doesn't satisfy another tenant.
 */
@FunctionalInterface
public interface Oid4vpIssuerTrust {

    IssuerKeyResolver forTenant(String tenantId);

    /** The same issuers for every tenant: a single-tenant verifier. */
    static Oid4vpIssuerTrust everywhere(IssuerKeyResolver resolver) {
        return tenantId -> resolver;
    }
}
