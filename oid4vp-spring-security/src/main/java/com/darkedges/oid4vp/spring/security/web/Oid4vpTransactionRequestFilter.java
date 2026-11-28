package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.darkedges.oid4vp.spring.security.transaction.Oid4vpTransaction;
import com.darkedges.oid4vp.spring.security.transaction.Oid4vpTransactions;
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
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Hosts the signed Request Object of an {@link Oid4vpTransaction} at its own {@code request_uri} (GET, and POST for
 * {@code request_uri_method=post}), as {@link Oid4vpRequestObjectFilter} does for a relying party's. The object carries the
 * transaction's request parameters and {@code expires_at}. Nothing is served once the transaction is answered or expired.
 */
public class Oid4vpTransactionRequestFilter extends OncePerRequestFilter {

    public static final String DEFAULT_PATH = "/oid4vp/transaction-request";
    public static final String DEFAULT_PATTERN = DEFAULT_PATH + "/{requestId}";

    private final RequestMatcher requestMatcher;
    private final Oid4vpTransactions transactions;
    private final RequestObjectSigningKeyResolver signingKeys;
    private final JWSAlgorithm signingAlgorithm;
    private Oid4vpTenantResolver tenantResolver = Oid4vpTenantResolver.SINGLE_TENANT;

    public Oid4vpTransactionRequestFilter(RequestMatcher requestMatcher, Oid4vpTransactions transactions,
                                          RequestObjectSigningKeyResolver signingKeys, JWSAlgorithm signingAlgorithm) {
        this.requestMatcher = requestMatcher;
        this.transactions = transactions;
        this.signingKeys = signingKeys;
        this.signingAlgorithm = signingAlgorithm;
    }

    /** Which tenant each request is for; single-tenant unless set. */
    public void setTenantResolver(Oid4vpTenantResolver tenantResolver) {
        this.tenantResolver = tenantResolver;
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

        Optional<Oid4vpTransaction> transaction =
                transactions.awaiting(tenantResolver.tenantId(request), result.getVariables().get("requestId"));
        Oid4vpAuthorizationRequestResolution resolution;
        try {
            if (transaction.isEmpty()) throw new IllegalArgumentException("no request is waiting here");
            resolution = transactions.request(transaction.get());
        } catch (IllegalArgumentException notFound) { // also a relying party removed since the transaction was made
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        Optional<JsonNode> signingKey = signingKeys.resolveSigningKey(transaction.get().registrationKey());
        if (signingKey.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        Map<String, String> parameters = new LinkedHashMap<>(transaction.get().requestParameters());
        parameters.put("expires_at", transaction.get().expiresAt().truncatedTo(ChronoUnit.SECONDS).toString());
        String walletNonce = "POST".equals(request.getMethod()) ? request.getParameter("wallet_nonce") : null;
        SignedJWT jwt = RequestObjectSigner.sign(
                resolution.request(), signingKey.get(), signingAlgorithm, Optional.ofNullable(walletNonce), parameters);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(Oid4vpRequestObjectFilter.CONTENT_TYPE);
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(jwt.serialize());
    }
}
