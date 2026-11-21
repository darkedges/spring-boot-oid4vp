package com.darkedges.oid4vc.tenancy;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.util.Objects;

/**
 * One tenant of an issuer or verifier deployment: an AuthStack environment that has enabled credential issuance or verification.
 *
 * <p>A tenant never lists its own hosts. It is reached on its platform subdomain ({@code <slug>.<platform host>}), on the shared
 * platform host's path ({@code <platform host>/t/<slug>}), or on a custom domain that AuthStack has verified for its environment
 * (see {@link com.darkedges.oid4vc.tenancy.domains.DomainDirectory}). So a tenant cannot claim a domain it does not own.
 *
 * @param id             the AuthStack environment id
 * @param organizationId the AuthStack organization that owns the environment ({@code null} only for a deployment's built-in tenant)
 * @param slug           its platform slug: a DNS label, unique in this deployment
 * @param enabled        a disabled tenant is not served at all
 * @param settings       this service's settings for the tenant (issuer or verifier settings). Its {@code secrets} object holds
 *                       write-only values (see {@link TenantSecrets})
 */
public record Tenant(String id, String organizationId, String slug, boolean enabled, ObjectNode settings,
                     Instant createdAt, Instant updatedAt) {

    public Tenant {
        Objects.requireNonNull(id, "id");
        Slugs.requireValid(slug);
        settings = settings == null ? JsonNodeFactory.instance.objectNode() : settings;
        createdAt = createdAt == null ? Instant.now() : createdAt;
        updatedAt = updatedAt == null ? createdAt : updatedAt;
    }

    public static Tenant create(String id, String organizationId, String slug) {
        return new Tenant(id, organizationId, slug, true, null, null, null);
    }

    public Tenant withSlug(String newSlug) {
        return new Tenant(id, organizationId, newSlug, enabled, settings, createdAt, Instant.now());
    }

    public Tenant withEnabled(boolean newEnabled) {
        return new Tenant(id, organizationId, slug, newEnabled, settings, createdAt, Instant.now());
    }

    public Tenant withSettings(ObjectNode newSettings) {
        return new Tenant(id, organizationId, slug, enabled, newSettings, createdAt, Instant.now());
    }
}
