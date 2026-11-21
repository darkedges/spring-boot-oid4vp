package com.darkedges.oid4vc.tenancy.admin;

import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;

/**
 * Checks a tenant's settings before they are saved: the issuer and the verifier each define what their settings may hold.
 * Returns the problems found, empty when the settings are acceptable.
 */
@FunctionalInterface
public interface TenantSettingsValidator {

    List<String> validate(ObjectNode settings);

    TenantSettingsValidator ANY = settings -> List.of();
}
