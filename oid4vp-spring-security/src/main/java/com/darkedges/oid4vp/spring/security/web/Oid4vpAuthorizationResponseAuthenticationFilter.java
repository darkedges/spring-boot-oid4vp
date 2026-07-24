package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Processes an incoming Authorization Response POST — either the Wallet's {@code direct_post} POST to
 * the Verifier's {@code response_uri}, or (when constructed with a
 * {@link Oid4vpDcApiAuthenticationConverter}) a page's relay of a Digital Credentials API result. Unlike
 * a typical browser-redirect login filter, success/failure both reply with a plain JSON body directly in
 * the HTTP response to the POST (no redirect) — the POST commonly doesn't come from the End-User's
 * top-level browser navigation.
 */
public class Oid4vpAuthorizationResponseAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger log = LoggerFactory.getLogger(Oid4vpAuthorizationResponseAuthenticationFilter.class);

    public static final String DEFAULT_RESPONSE_URI_PATTERN = "/login/oid4vp/direct-post/{registrationId}";
    public static final String DEFAULT_DC_API_RESPONSE_URI_PATTERN = "/login/oid4vp/dc-api/{registrationId}";

    private final AuthenticationConverter authenticationConverter;

    public Oid4vpAuthorizationResponseAuthenticationFilter(
            AuthenticationManager authenticationManager,
            RequestMatcher requestMatcher,
            AuthenticationConverter authenticationConverter) {
        super(requestMatcher, authenticationManager);
        this.authenticationConverter = authenticationConverter;
        setAuthenticationSuccessHandler((request, response, authResult) -> writeJson(response, HttpServletResponse.SC_OK, "{}"));
        setAuthenticationFailureHandler((request, response, exception) -> {
            Oid4vpErrorCode code = exception instanceof Oid4vpAuthenticationException oid4vpEx
                    ? oid4vpEx.errorCode()
                    : Oid4vpErrorCode.ACCESS_DENIED;
            log.warn("Authorization Response rejected ({}): {}", code.value(), exception.getMessage(), exception);
            writeJson(response, HttpServletResponse.SC_BAD_REQUEST, "{\"error\":\"" + code.value() + "\"}");
        });
    }

    public static RequestMatcher defaultRequestMatcher() {
        return PathPatternRequestMatcher.pathPattern(HttpMethod.POST, DEFAULT_RESPONSE_URI_PATTERN);
    }

    public static RequestMatcher defaultDcApiRequestMatcher() {
        return PathPatternRequestMatcher.pathPattern(HttpMethod.POST, DEFAULT_DC_API_RESPONSE_URI_PATTERN);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        Authentication token = authenticationConverter.convert(request);
        return getAuthenticationManager().authenticate(token);
    }

    private static void writeJson(HttpServletResponse response, int status, String body) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(body);
    }
}
