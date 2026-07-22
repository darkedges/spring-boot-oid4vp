package com.darkedges.oid4vp.spring.security.authentication;

import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import com.darkedges.oid4vp.core.response.Oid4vpException;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.core.response.VpToken;
import com.darkedges.oid4vp.core.response.VpTokenReader;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestContext;
import com.darkedges.oid4vp.verifier.AuthorizationResponseValidator;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;

import java.time.Clock;
import java.util.List;
import java.util.Map;

/**
 * Validates a received {@link Oid4vpAuthorizationResponseAuthenticationToken}'s {@code vp_token} against
 * the original Authorization Request (nonce, audience, DCQL query) and, on success, authenticates it as
 * an {@link Oid4vpAuthenticationToken} — analogous to how {@code OAuth2LoginAuthenticationProvider}
 * turns an authorization code exchange into an authenticated token.
 */
public class Oid4vpAuthorizationResponseAuthenticationProvider implements AuthenticationProvider {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AuthorizationResponseValidator validator;
    private final IssuerKeyResolver issuerKeyResolver;
    private final Clock clock;

    public Oid4vpAuthorizationResponseAuthenticationProvider(
            AuthorizationResponseValidator validator, IssuerKeyResolver issuerKeyResolver, Clock clock) {
        this.validator = validator;
        this.issuerKeyResolver = issuerKeyResolver;
        this.clock = clock;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return Oid4vpAuthorizationResponseAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Oid4vpAuthorizationResponseAuthenticationToken token = (Oid4vpAuthorizationResponseAuthenticationToken) authentication;
        Oid4vpAuthorizationRequestContext requestContext = token.requestContext();

        if (token.error().isPresent()) {
            String description = token.errorDescription().map(d -> " (" + d + ")").orElse("");
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.ACCESS_DENIED,
                    "Wallet returned an error: " + token.error().get() + description);
        }

        String vpTokenJson = token.vpTokenJson()
                .orElseThrow(() -> new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "vp_token is missing"));

        VpToken vpToken;
        try {
            vpToken = VpTokenReader.read(MAPPER.readTree(vpTokenJson));
        } catch (Exception e) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "vp_token is not valid JSON", e);
        }

        String expectedAudience = token.audienceOverride().orElseGet(() -> requestContext.clientId().fullClientId());

        Map<String, List<VerifiedPresentation>> verified;
        try {
            verified = validator.validate(
                    requestContext.dcqlQuery(), vpToken, requestContext.nonce(), expectedAudience, issuerKeyResolver, clock);
        } catch (Oid4vpException e) {
            throw new Oid4vpAuthenticationException(e.errorCode(), e.getMessage(), e);
        }

        Oid4vpPrincipal principal = new Oid4vpPrincipal(verified);
        Oid4vpAuthenticationToken authenticated = new Oid4vpAuthenticationToken(
                principal, AuthorityUtils.NO_AUTHORITIES, requestContext.transactionId().orElse(null));
        authenticated.setDetails(token.getDetails());
        return authenticated;
    }
}
