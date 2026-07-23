package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.request.AuthorizationRequest;
import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.darkedges.oid4vp.verifier.request.RequestObjectSigner;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Hosts a Verifier's Request Object for retrieval by reference ({@code request_uri}), per OpenID4VP 1.1
 * "Request URI Method post" (and its implied default, GET, per RFC9101).
 *
 * <p>GET: plain retrieval. POST ({@code request_uri_method=post}): the Wallet may send a
 * {@code wallet_nonce} form parameter, which — per spec — MUST be echoed back as a claim inside the
 * signed Request Object.
 *
 * <p>The response {@code Content-Type} is always {@code application/oauth-authz-req+jwt}, regardless of
 * the request's {@code Accept} header.
 *
 * <p>Error paths use {@code response.setStatus(...)} rather than {@code sendError(...)}: the latter
 * triggers a servlet-container forward to {@code /error}, re-entering the Spring Security filter chain —
 * which 403s unless the application happens to have permitAll'd {@code /error} too.
 */
public class Oid4vpRequestObjectFilter extends OncePerRequestFilter {

    public static final String DEFAULT_REQUEST_URI_PATTERN = "/oid4vp/request/{registrationId}";
    public static final String CONTENT_TYPE = "application/oauth-authz-req+jwt";

    private final RequestMatcher requestMatcher;
    private final Oid4vpAuthorizationRequestService requestService;
    private final RequestObjectSigningKeyResolver signingKeyResolver;
    private final JWSAlgorithm signingAlgorithm;

    public Oid4vpRequestObjectFilter(
            RequestMatcher requestMatcher,
            Oid4vpAuthorizationRequestService requestService,
            RequestObjectSigningKeyResolver signingKeyResolver,
            JWSAlgorithm signingAlgorithm) {
        this.requestMatcher = requestMatcher;
        this.requestService = requestService;
        this.signingKeyResolver = signingKeyResolver;
        this.signingAlgorithm = signingAlgorithm;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        RequestMatcher.MatchResult result = requestMatcher.matcher(request);
        boolean methodSupported = "GET".equals(request.getMethod()) || "POST".equals(request.getMethod());
        if (!result.isMatch() || !methodSupported) {
            chain.doFilter(request, response);
            return;
        }

        String registrationId = result.getVariables().get("registrationId");
        if (registrationId == null) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        AuthorizationRequest authorizationRequest;
        try {
            authorizationRequest = requestService.resolve(registrationId).request();
        } catch (IllegalArgumentException notFound) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        Optional<JsonNode> signingKey = signingKeyResolver.resolveSigningKey(registrationId);
        if (signingKey.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        String walletNonce = "POST".equals(request.getMethod()) ? request.getParameter("wallet_nonce") : null;
        SignedJWT jwt = RequestObjectSigner.sign(
                authorizationRequest, signingKey.get(), signingAlgorithm, Optional.ofNullable(walletNonce));

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(CONTENT_TYPE);
        response.getWriter().write(jwt.serialize());
    }
}
