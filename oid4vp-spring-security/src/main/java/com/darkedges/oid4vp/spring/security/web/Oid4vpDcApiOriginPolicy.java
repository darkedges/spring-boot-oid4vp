package com.darkedges.oid4vp.spring.security.web;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Which browser origins may relay a Digital Credentials API response for a registration. The Wallet binds the presentation to the
 * origin of the page that asked for it, and this verifier checks the presentation against the {@code Origin} the response arrives
 * with: both are the requesting page's. Without a policy any origin is accepted, so a page elsewhere that obtained this verifier's
 * request could relay a presentation it asked a Wallet for. A policy limits that to the verifier's own pages.
 */
@FunctionalInterface
public interface Oid4vpDcApiOriginPolicy {

    boolean allows(HttpServletRequest request, String registrationKey, String origin);

    /** Any origin: the behaviour before origin policies. */
    Oid4vpDcApiOriginPolicy ANY = (request, registrationKey, origin) -> true;
}
