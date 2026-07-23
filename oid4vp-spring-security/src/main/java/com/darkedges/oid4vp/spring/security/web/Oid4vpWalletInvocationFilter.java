package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Redirects the End-User's browser to a Wallet's {@code authorization_endpoint} with {@code client_id}
 * and {@code request_uri} attached — the same-device invocation a web-based Wallet expects, as opposed to
 * a QR code or {@code openid4vp://} deep link. Requires the target registration's
 * {@link Oid4vpRelyingPartyRegistration#walletAuthorizationEndpoint()} to be configured; there's no
 * request parameter to supply or override it here, since accepting an arbitrary caller-supplied redirect
 * target would be an open redirect.
 *
 * <p>Intended uses: pointing at a real web-based Wallet in production, or — the reason this exists —
 * pointing at an OpenID Foundation conformance suite Verifier test plan's exported
 * {@code authorization_endpoint}, which expects to be invoked exactly this way ("in the same way a
 * web-based wallet would be invoked").
 *
 * <p>Requires signed {@code request_uri} hosting ({@link Oid4vpRequestObjectFilter}) to actually be
 * useful — an unsigned {@code redirect_uri:}-scheme request has nothing a real Wallet would trust.
 *
 * <p>Error paths use {@code response.setStatus(...)} rather than {@code sendError(...)}: the latter
 * triggers a servlet-container forward to {@code /error}, re-entering the Spring Security filter chain —
 * which 403s unless the application happens to have permitAll'd {@code /error} too.
 */
public class Oid4vpWalletInvocationFilter extends OncePerRequestFilter {

    public static final String DEFAULT_INVOKE_URI_PATTERN = "/oid4vp/invoke/{registrationId}";

    private final RequestMatcher requestMatcher;
    private final Oid4vpRelyingPartyRegistrationRepository registrations;
    private final String requestUriBase;

    /** @param requestUriBase e.g. {@code "https://verifier.example.org/oid4vp/request"} — the
     *                        registrationId is appended to build the {@code request_uri} handed to the
     *                        Wallet; must be reachable by the Wallet being invoked and match wherever
     *                        {@link Oid4vpRequestObjectFilter} is actually hosted. */
    public Oid4vpWalletInvocationFilter(
            RequestMatcher requestMatcher, Oid4vpRelyingPartyRegistrationRepository registrations, String requestUriBase) {
        this.requestMatcher = requestMatcher;
        this.registrations = registrations;
        this.requestUriBase = requestUriBase;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        RequestMatcher.MatchResult result = requestMatcher.matcher(request);
        if (!result.isMatch()) {
            chain.doFilter(request, response);
            return;
        }

        String registrationId = result.getVariables().get("registrationId");
        Optional<Oid4vpRelyingPartyRegistration> registration =
                registrationId == null ? Optional.empty() : registrations.findByRegistrationId(registrationId);
        if (registration.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        Optional<URI> walletAuthorizationEndpoint = registration.get().walletAuthorizationEndpoint();
        if (walletAuthorizationEndpoint.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_NOT_IMPLEMENTED);
            return;
        }

        String requestUri = requestUriBase + "/" + registrationId;
        String clientId = registration.get().clientId().fullClientId();
        String endpoint = walletAuthorizationEndpoint.get().toString();
        String separator = walletAuthorizationEndpoint.get().getQuery() == null ? "?" : "&";

        String redirectUri = endpoint + separator
                + "client_id=" + urlEncode(clientId)
                + "&request_uri=" + urlEncode(requestUri);

        response.sendRedirect(redirectUri);
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
