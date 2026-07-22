package com.darkedges.oid4vp.spring.security.authentication;

import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Optional;

/**
 * An unauthenticated token representing a received (not yet validated) Authorization Response — from
 * either {@code direct_post}/{@code direct_post.jwt} or the Digital Credentials API — carrying either a
 * {@code vp_token} (+ {@code state}) or a Wallet-reported error.
 *
 * @implNote {@code audienceOverride} exists for the Digital Credentials API: since there is no
 * {@code client_id}-based channel there, the expected audience is {@code origin:<origin>} instead of the
 * Verifier's Client Identifier (OpenID4VP 1.1, "Request" under "OpenID4VP over the Digital Credentials API").
 */
public class Oid4vpAuthorizationResponseAuthenticationToken extends AbstractAuthenticationToken {

    private final Oid4vpAuthorizationRequestContext requestContext;
    private final String vpTokenJson;
    private final String error;
    private final String errorDescription;
    private final String audienceOverride;

    public Oid4vpAuthorizationResponseAuthenticationToken(Oid4vpAuthorizationRequestContext requestContext, String vpTokenJson) {
        this(requestContext, vpTokenJson, null);
    }

    public Oid4vpAuthorizationResponseAuthenticationToken(
            Oid4vpAuthorizationRequestContext requestContext, String vpTokenJson, String audienceOverride) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.requestContext = requestContext;
        this.vpTokenJson = vpTokenJson;
        this.error = null;
        this.errorDescription = null;
        this.audienceOverride = audienceOverride;
        setAuthenticated(false);
    }

    public static Oid4vpAuthorizationResponseAuthenticationToken ofError(
            Oid4vpAuthorizationRequestContext requestContext, String error, String errorDescription) {
        return new Oid4vpAuthorizationResponseAuthenticationToken(requestContext, error, errorDescription, null);
    }

    public static Oid4vpAuthorizationResponseAuthenticationToken ofError(
            Oid4vpAuthorizationRequestContext requestContext, String error, String errorDescription, String audienceOverride) {
        return new Oid4vpAuthorizationResponseAuthenticationToken(requestContext, error, errorDescription, audienceOverride);
    }

    private Oid4vpAuthorizationResponseAuthenticationToken(
            Oid4vpAuthorizationRequestContext requestContext, String error, String errorDescription, String audienceOverride) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.requestContext = requestContext;
        this.vpTokenJson = null;
        this.error = error;
        this.errorDescription = errorDescription;
        this.audienceOverride = audienceOverride;
        setAuthenticated(false);
    }

    public Oid4vpAuthorizationRequestContext requestContext() {
        return requestContext;
    }

    public Optional<String> vpTokenJson() {
        return Optional.ofNullable(vpTokenJson);
    }

    public Optional<String> error() {
        return Optional.ofNullable(error);
    }

    public Optional<String> errorDescription() {
        return Optional.ofNullable(errorDescription);
    }

    /** {@code origin:<origin>}, when this response arrived via the Digital Credentials API; otherwise
     * empty (the Verifier's own Client Identifier is used as the expected audience). */
    public Optional<String> audienceOverride() {
        return Optional.ofNullable(audienceOverride);
    }

    @Override
    public Object getCredentials() {
        return vpTokenJson;
    }

    @Override
    public Object getPrincipal() {
        return requestContext;
    }
}
