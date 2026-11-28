package com.darkedges.oid4vc.tenancy.web;

import com.darkedges.oid4vc.tenancy.TenantContext;
import com.darkedges.oid4vc.tenancy.TenantResolver;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ServletRequestPathUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

/**
 * Resolves each request's tenant ({@link TenantResolver}) before anything else, Spring Security included, and stores it as the
 * {@link TenantContext#ATTRIBUTE} request attribute.
 *
 * <p>For path routing it also removes {@code /t/<slug>} (or the {@code /t/<slug>} after a well-known name), so the application's
 * controllers, security rules and filters see the same paths a single-tenant deployment would: {@code /t/bank/token} is handled as
 * {@code /token}, and {@code /.well-known/openid-credential-issuer/t/bank} as {@code /.well-known/openid-credential-issuer}.
 *
 * <p>A request with no tenant gets 404, except on the deployment's platform paths ({@code oid4vc.tenancy.platform-paths}, such as
 * the admin API), which are served without one.
 */
public final class TenantResolutionFilter extends OncePerRequestFilter {

    private final TenantResolver resolver;
    private final List<String> platformPaths;

    public TenantResolutionFilter(TenantResolver resolver, List<String> platformPaths) {
        this.resolver = resolver;
        this.platformPaths = List.copyOf(platformPaths);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String contextPath = request.getContextPath() == null ? "" : request.getContextPath();
        String uri = request.getRequestURI();
        String path = uri.startsWith(contextPath) ? uri.substring(contextPath.length()) : uri;

        Optional<TenantResolver.Resolution> resolution = resolver.resolve(new TenantResolver.Request(
                request.getHeader("Host"), request.getHeader("X-Forwarded-Host"), request.getScheme(),
                request.getHeader("X-Forwarded-Proto"), path));

        if (resolution.isEmpty()) {
            if (isPlatformPath(path)) {
                chain.doFilter(request, response);
                return;
            }
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.setContentType("application/json");
            response.getOutputStream().write("{\"error\":\"not_found\",\"error_description\":\"No tenant is served here\"}"
                    .getBytes(StandardCharsets.UTF_8));
            return;
        }

        TenantContext context = resolution.get().context();
        request.setAttribute(TenantContext.ATTRIBUTE, context);
        String strippedPath = resolution.get().path();
        HttpServletRequest forChain = strippedPath.equals(path) ? request : new TenantPathRequest(request, contextPath, strippedPath);
        // Spring caches a parsed request path per request; drop any parsed from the original path.
        ServletRequestPathUtils.clearParsedRequestPath(forChain);
        chain.doFilter(forChain, response);
    }

    private boolean isPlatformPath(String path) {
        for (String pattern : platformPaths) {
            if (pattern.endsWith("/**")) {
                String prefix = pattern.substring(0, pattern.length() - 3);
                if (path.equals(prefix) || path.startsWith(prefix + "/")) return true;
            } else if (path.equals(pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The request as a single-tenant deployment would have received it: the {@code /t/<slug>} part removed from its path. Only for
     * the request itself: on a forward or an error dispatch the container changes the path beneath this wrapper, and that new path
     * is the answer.
     */
    static final class TenantPathRequest extends HttpServletRequestWrapper {

        private final String contextPath;
        private final String path;

        TenantPathRequest(HttpServletRequest request, String contextPath, String path) {
            super(request);
            this.contextPath = contextPath;
            this.path = path;
        }

        private boolean dispatchedElsewhere() {
            DispatcherType type = getDispatcherType();
            return type == DispatcherType.FORWARD || type == DispatcherType.ERROR;
        }

        /**
         * A relative dispatch (the welcome page forwards to {@code index.html}) is resolved against the path the application sees.
         * The container would resolve it against {@code /t/<slug>/…}, which no rule or mapping of the application matches.
         */
        @Override
        public RequestDispatcher getRequestDispatcher(String target) {
            if (target == null || target.startsWith("/") || dispatchedElsewhere()) return super.getRequestDispatcher(target);
            return super.getRequestDispatcher(path.substring(0, path.lastIndexOf('/') + 1) + (path.contains("/") ? "" : "/") + target);
        }

        @Override
        public String getRequestURI() {
            return dispatchedElsewhere() ? super.getRequestURI() : contextPath + path;
        }

        @Override
        public StringBuffer getRequestURL() {
            StringBuffer original = super.getRequestURL();
            if (dispatchedElsewhere()) return original;
            String originalUri = super.getRequestURI();
            int at = original.lastIndexOf(originalUri);
            return at < 0 ? original : new StringBuffer(original.substring(0, at)).append(getRequestURI());
        }

        @Override
        public String getServletPath() {
            return dispatchedElsewhere() ? super.getServletPath() : path;
        }

        @Override
        public String getPathInfo() {
            return dispatchedElsewhere() ? super.getPathInfo() : null;
        }
    }
}
