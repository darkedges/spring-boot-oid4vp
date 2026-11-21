package com.darkedges.oid4vc.tenancy;

import java.util.List;
import java.util.Optional;

/** Where a deployment keeps its tenants. */
public interface TenantRepository {

    Optional<Tenant> findById(String id);

    Optional<Tenant> findBySlug(String slug);

    List<Tenant> findAll();

    /**
     * Creates or replaces the tenant with this id.
     *
     * @throws SlugTakenException if another tenant already has the slug
     */
    Tenant save(Tenant tenant);

    boolean delete(String id);

    /** Thrown when a slug already belongs to another tenant. */
    final class SlugTakenException extends RuntimeException {
        public SlugTakenException(String slug) {
            super("the slug \"" + slug + "\" belongs to another tenant");
        }
    }
}
