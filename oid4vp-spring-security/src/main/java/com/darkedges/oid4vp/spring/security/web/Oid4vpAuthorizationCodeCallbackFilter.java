package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.request.TokenEndpointClient;
import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationException;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationToken;
import com.darkedges.oid4vp.spring.security.registration.CodeFlowConfig;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;
import java.net.URI;

/**
 * Completes the OAuth 2.0 Authorization Code Grant ({@code response_type=code}) flow: the End-User's
 * browser lands here after the Wallet's redirect, carrying {@code ?code=...&state=...} (or
 * {@code ?error=...&state=...}). Looks up the pending {@link Oid4vpAuthorizationRequestContext} by
 * {@code state}, exchanges {@code code} at the registration's token endpoint via the supplied
 * {@link TokenEndpointClient}, and authenticates the resulting {@code vp_token} through the same
 * {@link AuthenticationManager} (and so the same {@code AuthorizationResponseValidator} validation) used
 * for {@code direct_post} — {@link Oid4vpAuthorizationResponseAuthenticationToken} is fully transport
 * agnostic, so no changes were needed there.
 */
public class Oid4vpAuthorizationCodeCallbackFilter extends AbstractAuthenticationProcessingFilter {

    public static final String DEFAULT_CALLBACK_URI_PATTERN = "/oid4vp/callback/{registrationId}";

    private final RequestMatcher requestMatcher;
    private final Oid4vpAuthorizationRequestRepository requestRepository;
    private final Oid4vpRelyingPartyRegistrationRepository registrations;
    private final TokenEndpointClient tokenEndpointClient;

    /** @param successRedirectUri if non-null, a successful exchange redirects the browser here (e.g. back
     *                            to a demo page) instead of writing a bare {@code {}} JSON body. */
    public Oid4vpAuthorizationCodeCallbackFilter(
            RequestMatcher requestMatcher,
            AuthenticationManager authenticationManager,
            Oid4vpAuthorizationRequestRepository requestRepository,
            Oid4vpRelyingPartyRegistrationRepository registrations,
            TokenEndpointClient tokenEndpointClient,
            String successRedirectUri) {
        super(requestMatcher, authenticationManager);
        this.requestMatcher = requestMatcher;
        this.requestRepository = requestRepository;
        this.registrations = registrations;
        this.tokenEndpointClient = tokenEndpointClient;
        setAuthenticationSuccessHandler((request, response, authResult) -> {
            if (successRedirectUri != null) {
                response.sendRedirect(successRedirectUri);
            } else {
                writeJson(response, HttpServletResponse.SC_OK, "{}");
            }
        });
        // response.setStatus(...) rather than sendError(...): the latter triggers a servlet-container
        // forward to /error, re-entering the Spring Security filter chain — which 403s unless the
        // application happens to have permitAll'd /error too.
        setAuthenticationFailureHandler((request, response, exception) ->
                response.setStatus(HttpServletResponse.SC_FORBIDDEN));
    }

    public static RequestMatcher defaultRequestMatcher() {
        return PathPatternRequestMatcher.pathPattern(HttpMethod.GET, DEFAULT_CALLBACK_URI_PATTERN);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        RequestMatcher.MatchResult result = requestMatcher.matcher(request);
        String registrationId = result.getVariables().get("registrationId");

        String state = request.getParameter("state");
        if (state == null || state.isBlank()) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "missing required \"state\" parameter");
        }

        Oid4vpAuthorizationRequestContext context = requestRepository.consume(state)
                .orElseThrow(() -> new Oid4vpAuthenticationException(
                        Oid4vpErrorCode.INVALID_REQUEST, "unknown or expired \"state\": " + state));

        String error = request.getParameter("error");
        if (error != null) {
            Oid4vpAuthorizationResponseAuthenticationToken errorToken = Oid4vpAuthorizationResponseAuthenticationToken.ofError(
                    context, error, request.getParameter("error_description"));
            return getAuthenticationManager().authenticate(errorToken);
        }

        String code = request.getParameter("code");
        if (code == null || code.isBlank()) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "missing required \"code\" parameter");
        }

        Oid4vpRelyingPartyRegistration registration = registrations.findByRegistrationId(registrationId)
                .orElseThrow(() -> new Oid4vpAuthenticationException(
                        Oid4vpErrorCode.INVALID_REQUEST, "unknown relying party registration: " + registrationId));
        CodeFlowConfig codeFlow = registration.codeFlow()
                .orElseThrow(() -> new Oid4vpAuthenticationException(
                        Oid4vpErrorCode.INVALID_REQUEST, "registration is not configured for the code flow: " + registrationId));
        URI tokenEndpoint = codeFlow.tokenEndpoint()
                .orElseThrow(() -> new Oid4vpAuthenticationException(
                        Oid4vpErrorCode.INVALID_REQUEST, "no wallet-token-endpoint configured for registration: " + registrationId));
        String codeVerifier = context.codeVerifier()
                .orElseThrow(() -> new Oid4vpAuthenticationException(
                        Oid4vpErrorCode.INVALID_REQUEST, "no code_verifier stored for this transaction"));

        JsonNode tokenResponse;
        try {
            tokenResponse = tokenEndpointClient.exchange(
                    tokenEndpoint, code, codeFlow.redirectUri().toString(),
                    registration.clientId().fullClientId(), codeVerifier);
        } catch (Exception e) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.WALLET_UNAVAILABLE, "token endpoint exchange failed", e);
        }

        if (tokenResponse == null || !tokenResponse.hasNonNull("vp_token")) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "token response did not contain vp_token");
        }

        String vpTokenJson = tokenResponse.get("vp_token").toString();
        Oid4vpAuthorizationResponseAuthenticationToken token =
                new Oid4vpAuthorizationResponseAuthenticationToken(context, vpTokenJson);
        return getAuthenticationManager().authenticate(token);
    }

    private static void writeJson(HttpServletResponse response, int status, String body) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(body);
    }
}
