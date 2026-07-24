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
 * {@code responseEncryptionPublicJwkJson} — see
 * {@link com.darkedges.oid4vp.core.response.PresentationVerificationParams#responseEncryptionPublicJwk()}
 * — is only ever present for a successfully decrypted response; meaningless (and always empty) on an
 * error token, since there's no presentation to verify.
 */
public class Oid4vpAuthorizationResponseAuthenticationToken extends AbstractAuthenticationToken {

    private final Oid4vpAuthorizationRequestContext requestContext;
    private final String vpTokenJson;
    private final String error;
    private final String errorDescription;
    private final String audienceOverride;
    private final String responseEncryptionPublicJwkJson;

    private Oid4vpAuthorizationResponseAuthenticationToken(
            Oid4vpAuthorizationRequestContext requestContext, String vpTokenJson, String error, String errorDescription,
            String audienceOverride, String responseEncryptionPublicJwkJson) {
        super(AuthorityUtils.NO_AUTHORITIES);
        this.requestContext = requestContext;
        this.vpTokenJson = vpTokenJson;
        this.error = error;
        this.errorDescription = errorDescription;
        this.audienceOverride = audienceOverride;
        this.responseEncryptionPublicJwkJson = responseEncryptionPublicJwkJson;
        setAuthenticated(false);
    }

    public Oid4vpAuthorizationResponseAuthenticationToken(Oid4vpAuthorizationRequestContext requestContext, String vpTokenJson) {
        this(requestContext, vpTokenJson, null, null, null, null);
    }

    public Oid4vpAuthorizationResponseAuthenticationToken(
            Oid4vpAuthorizationRequestContext requestContext, String vpTokenJson, String audienceOverride) {
        this(requestContext, vpTokenJson, null, null, audienceOverride, null);
    }

    public Oid4vpAuthorizationResponseAuthenticationToken(
            Oid4vpAuthorizationRequestContext requestContext, String vpTokenJson, String audienceOverride,
            String responseEncryptionPublicJwkJson) {
        this(requestContext, vpTokenJson, null, null, audienceOverride, responseEncryptionPublicJwkJson);
    }

    public static Oid4vpAuthorizationResponseAuthenticationToken ofError(
            Oid4vpAuthorizationRequestContext requestContext, String error, String errorDescription) {
        return ofError(requestContext, error, errorDescription, null);
    }

    public static Oid4vpAuthorizationResponseAuthenticationToken ofError(
            Oid4vpAuthorizationRequestContext requestContext, String error, String errorDescription, String audienceOverride) {
        return new Oid4vpAuthorizationResponseAuthenticationToken(requestContext, null, error, errorDescription, audienceOverride, null);
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

    /** The response-encryption public key (raw JSON, kept crypto-library-agnostic) this response was
     * actually decrypted with — see {@link com.darkedges.oid4vp.core.response.PresentationVerificationParams}. */
    public Optional<String> responseEncryptionPublicJwkJson() {
        return Optional.ofNullable(responseEncryptionPublicJwkJson);
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
