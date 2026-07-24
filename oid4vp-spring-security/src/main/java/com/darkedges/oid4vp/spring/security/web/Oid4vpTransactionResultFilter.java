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
 *
 * <p>Error paths use {@code response.setStatus(...)} rather than {@code sendError(...)}: the latter
 * triggers a servlet-container forward to {@code /error}, re-entering the Spring Security filter chain —
 * which 403s unless the application happens to have permitAll'd {@code /error} too.
 */
public class Oid4vpTransactionResultFilter extends OncePerRequestFilter {

    public static final String DEFAULT_RESULT_URI_PATTERN = "/oid4vp/result/{transactionId}";

    private final RequestMatcher requestMatcher;
    private final Oid4vpTransactionResultRepository transactionResultRepository;
    private final String successRedirectUri;
    private SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public Oid4vpTransactionResultFilter(RequestMatcher requestMatcher, Oid4vpTransactionResultRepository transactionResultRepository) {
        this(requestMatcher, transactionResultRepository, null);
    }

    /**
     * @param successRedirectUri if non-null, a successful handoff redirects the browser here (e.g. back to
     *                           a demo page) instead of writing the default {@code {}} JSON body.
     */
    public Oid4vpTransactionResultFilter(RequestMatcher requestMatcher, Oid4vpTransactionResultRepository transactionResultRepository, String successRedirectUri) {
        this.requestMatcher = requestMatcher;
        this.transactionResultRepository = transactionResultRepository;
        this.successRedirectUri = successRedirectUri;
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
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        Optional<Authentication> authentication = transactionResultRepository.consume(transactionId, responseCode);
        if (authentication.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication.get());
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        if (successRedirectUri != null) {
            response.sendRedirect(successRedirectUri);
            return;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.getWriter().write("{}");
    }
}
