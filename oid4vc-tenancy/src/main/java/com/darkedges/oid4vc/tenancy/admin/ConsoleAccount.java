package com.darkedges.oid4vc.tenancy.admin;

import java.util.Map;

/**
 * A person signed in to the AuthStack console, as AuthStack's {@code GET /api/auth/me} describes them.
 *
 * @param role         {@code ADMIN} (platform operator: every tenant), {@code ORG_ADMIN} (their organization's environments) or
 *                     {@code ORG_VIEWER} (read only)
 * @param environments the environments their organization owns, id to name: the proof that an environment is theirs
 */
public record ConsoleAccount(String userId, String email, Role role, String organizationId, Map<String, String> environments) {

    public enum Role { ADMIN, ORG_ADMIN, ORG_VIEWER }

    public ConsoleAccount {
        environments = environments == null ? Map.of() : Map.copyOf(environments);
    }

    public boolean isPlatformAdmin() {
        return role == Role.ADMIN;
    }

    /** May see this environment's tenant. */
    public boolean mayRead(String environmentId, String tenantOrganizationId) {
        if (isPlatformAdmin()) return true;
        if (!environments.containsKey(environmentId)) return false;
        return tenantOrganizationId == null || tenantOrganizationId.equals(organizationId);
    }

    /** May change this environment's tenant. */
    public boolean mayWrite(String environmentId, String tenantOrganizationId) {
        return role != Role.ORG_VIEWER && mayRead(environmentId, tenantOrganizationId);
    }

    public String who() {
        return (email != null ? email : userId) + " (" + role + ")";
    }
}
