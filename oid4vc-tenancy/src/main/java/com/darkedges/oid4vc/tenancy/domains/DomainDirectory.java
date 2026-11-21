package com.darkedges.oid4vc.tenancy.domains;

import java.util.Optional;

/**
 * Which environment a custom domain belongs to. Only domains whose owner proved control of them, and that are ready to serve
 * (AuthStack: verified by a DNS TXT challenge, certificate issued), are known here. A tenant cannot add one itself.
 */
public interface DomainDirectory {

    /** The ACTIVE custom domain for this (normalized) host, if any. */
    Optional<DomainBinding> lookup(String host);

    /** Knows no domains: tenants are reached only on platform subdomains and paths. */
    DomainDirectory NONE = host -> Optional.empty();

    /**
     * A custom domain linked to an environment.
     *
     * @param host           normalized host name
     * @param environmentId  the AuthStack environment, which is the tenant id
     * @param organizationId the organization owning the environment, when known
     */
    record DomainBinding(String host, String environmentId, String organizationId) {}
}
