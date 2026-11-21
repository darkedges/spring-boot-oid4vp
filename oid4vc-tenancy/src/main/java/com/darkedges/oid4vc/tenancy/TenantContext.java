package com.darkedges.oid4vc.tenancy;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.Objects;
import java.util.Optional;

/**
 * The tenant a request is for, and the URL it was reached on.
 *
 * <p>The base URL is the tenant's identifier on that URL: an issuer's {@code credential_issuer}, a verifier's {@code response_uri}
 * base. It is {@code https://bank.issuer.zkp.au} (platform subdomain), {@code https://issuer.bank.example} (custom domain) or
 * {@code https://issuer.zkp.au/t/bank} (path).
 *
 * @param tenant     the tenant
 * @param routing    how the request reached it
 * @param scheme     {@code https} (or {@code http} in development)
 * @param authority  host, with the port when it is not the scheme's default
 * @param pathPrefix {@code ""}, or {@code /t/<slug>} for path routing
 */
public record TenantContext(Tenant tenant, Routing routing, String scheme, String authority, String pathPrefix) {

    /** The request attribute holding the context, set by {@link com.darkedges.oid4vc.tenancy.web.TenantResolutionFilter}. */
    public static final String ATTRIBUTE = TenantContext.class.getName();

    public enum Routing { PLATFORM_SUBDOMAIN, CUSTOM_DOMAIN, PATH, DEFAULT }

    public TenantContext {
        Objects.requireNonNull(tenant, "tenant");
        Objects.requireNonNull(routing, "routing");
        pathPrefix = pathPrefix == null ? "" : pathPrefix;
    }

    public String tenantId() {
        return tenant.id();
    }

    public String origin() {
        return scheme + "://" + authority;
    }

    /** The tenant's identifier on this URL, without a trailing slash. */
    public String baseUrl() {
        return origin() + pathPrefix;
    }

    /** An endpoint of this tenant: {@code path} is the path a single-tenant deployment would use, such as {@code /token}. */
    public String url(String path) {
        return baseUrl() + (path.startsWith("/") ? path : "/" + path);
    }

    /**
     * The well-known URL for this tenant's metadata, per RFC 8414 section 3.1: the well-known segment goes between the host and the
     * identifier's path, so {@code https://issuer.zkp.au/t/bank} has {@code https://issuer.zkp.au/.well-known/<name>/t/bank}.
     */
    public String wellKnown(String name) {
        return origin() + "/.well-known/" + name + pathPrefix;
    }

    public static Optional<TenantContext> from(HttpServletRequest request) {
        return Optional.ofNullable((TenantContext) request.getAttribute(ATTRIBUTE));
    }

    public static TenantContext require(HttpServletRequest request) {
        return from(request).orElseThrow(() -> new IllegalStateException("no tenant for this request"));
    }

    /** The current request's tenant, from Spring's request context (for code that has no request at hand). */
    public static Optional<TenantContext> current() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes == null) return Optional.empty();
        return Optional.ofNullable((TenantContext) attributes.getAttribute(ATTRIBUTE, RequestAttributes.SCOPE_REQUEST));
    }
}
