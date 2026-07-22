package com.darkedges.oid4vp.spring.security.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Completes the same-device {@code response_code}/{@code redirect_uri} handoff: the End-User's browser
 * lands here after the Wallet's redirect (OpenID4VP 1.1, "Response Mode direct_post" reference design,
 * steps 7–9, collapsed into one hop — see {@link Oid4vpSameDeviceAuthenticationSuccessHandler}). Looks up
 * the Authorization Response by {@code transactionId} + {@code response_code}, and if found, establishes
 * the {@code SecurityContext} for this browser session.
 */
public class Oid4vpTransactionResultFilter extends OncePerRequestFilter {

    public static final String DEFAULT_RESULT_URI_PATTERN = "/oid4vp/result/{transactionId}";

    private final RequestMatcher requestMatcher;
    private final Oid4vpTransactionResultRepository transactionResultRepository;
    private SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public Oid4vpTransactionResultFilter(RequestMatcher requestMatcher, Oid4vpTransactionResultRepository transactionResultRepository) {
        this.requestMatcher = requestMatcher;
        this.transactionResultRepository = transactionResultRepository;
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        RequestMatcher.MatchResult result = requestMatcher.matcher(request);
        if (!result.isMatch()) {
            chain.doFilter(request, response);
            return;
        }

        String transactionId = result.getVariables().get("transactionId");
        String responseCode = request.getParameter("response_code");
        if (transactionId == null || responseCode == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "missing transactionId or response_code");
            return;
        }

        Optional<Authentication> authentication = transactionResultRepository.consume(transactionId, responseCode);
        if (authentication.isEmpty()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "unknown or already-consumed transaction");
            return;
        }

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication.get());
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.getWriter().write("{}");
    }
}
