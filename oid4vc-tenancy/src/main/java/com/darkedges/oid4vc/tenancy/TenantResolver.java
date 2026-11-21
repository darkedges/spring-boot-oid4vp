package com.darkedges.oid4vc.tenancy;

import com.darkedges.oid4vc.tenancy.TenantContext.Routing;
import com.darkedges.oid4vc.tenancy.domains.DomainDirectory;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Finds the tenant a request is for, in this order:
 * <ol>
 *   <li>a platform subdomain, {@code <slug>.<platform host>};</li>
 *   <li>a custom domain the {@link DomainDirectory} knows (verified and active in AuthStack);</li>
 *   <li>on a platform host itself, the path {@code /t/<slug>/...}, or the inserted well-known form
 *       {@code /.well-known/<name>/t/<slug>};</li>
 *   <li>on a platform host itself, the deployment's default tenant, if it has one.</li>
 * </ol>
 * Anything else has no tenant. A disabled tenant is never served.
 *
 * <p>{@code X-Forwarded-Host} (and {@code X-Forwarded-Proto}) count only when the deployment trusts its proxy, and the forwarded host
 * only when it is a platform host or one of the hosts above: a client cannot pick a tenant by sending the header itself.
 */
public final class TenantResolver {

    /** What the resolver needs from a request. {@code path} excludes the servlet context path. */
    public record Request(String host, String forwardedHost, String scheme, String forwardedProto, String path) {}

    /** The tenant, and the path a single-tenant deployment would have seen (the {@code /t/<slug>} part removed). */
    public record Resolution(TenantContext context, String path) {}

    private final TenantRepository tenants;
    private final DomainDirectory domains;
    private final Set<String> platformHosts;
    private final String defaultTenantId;
    private final boolean trustForwardedHeaders;
    private final String publicScheme;

    /**
     * @param platformHosts         the shared hosts, such as {@code issuer.zkp.au} (and {@code localhost} in development)
     * @param defaultTenantId       the tenant served on a platform host without {@code /t/<slug>}, or {@code null}
     * @param trustForwardedHeaders whether a reverse proxy in front sets {@code X-Forwarded-Host} / {@code -Proto}
     * @param publicScheme          forces the scheme of every URL ({@code https} behind a TLS-terminating proxy), or {@code null}
     */
    public TenantResolver(TenantRepository tenants, DomainDirectory domains, List<String> platformHosts, String defaultTenantId,
                          boolean trustForwardedHeaders, String publicScheme) {
        this.tenants = tenants;
        this.domains = domains;
        this.platformHosts = platformHosts.stream().map(Slugs::normalizeHost).collect(Collectors.toUnmodifiableSet());
        this.defaultTenantId = defaultTenantId == null || defaultTenantId.isBlank() ? null : defaultTenantId;
        this.trustForwardedHeaders = trustForwardedHeaders;
        this.publicScheme = publicScheme == null || publicScheme.isBlank() ? null : publicScheme;
    }

    public Optional<Resolution> resolve(Request request) {
        String authority = effectiveAuthority(request);
        String host = Slugs.normalizeHost(authority);
        String scheme = scheme(request);
        String path = request.path() == null || request.path().isEmpty() ? "/" : request.path();

        Optional<Tenant> bySubdomain = platformSubdomainSlug(host).flatMap(tenants::findBySlug);
        if (bySubdomain.isPresent()) {
            return served(bySubdomain.get(), Routing.PLATFORM_SUBDOMAIN, scheme, authority, "", path);
        }
        if (platformHosts.contains(host)) {
            return onPlatformHost(scheme, authority, path);
        }
        return domains.lookup(host)
                .flatMap(binding -> tenants.findById(binding.environmentId()))
                .flatMap(tenant -> served(tenant, Routing.CUSTOM_DOMAIN, scheme, authority, "", path));
    }

    /** Whether this host could be one of the deployment's: a platform host, a platform subdomain, or a known custom domain. */
    public boolean isKnownHost(String hostOrAuthority) {
        String host = Slugs.normalizeHost(hostOrAuthority);
        return platformHosts.contains(host) || platformSubdomainSlug(host).isPresent() || domains.lookup(host).isPresent();
    }

    private Optional<Resolution> onPlatformHost(String scheme, String authority, String path) {
        PathTenant pathTenant = PathTenant.parse(path);
        if (pathTenant != null) {
            return tenants.findBySlug(pathTenant.slug())
                    .flatMap(t -> served(t, Routing.PATH, scheme, authority, "/t/" + pathTenant.slug(), pathTenant.remainder()));
        }
        if (defaultTenantId == null) return Optional.empty();
        return tenants.findById(defaultTenantId).flatMap(t -> served(t, Routing.DEFAULT, scheme, authority, "", path));
    }

    private static Optional<Resolution> served(Tenant tenant, Routing routing, String scheme, String authority, String prefix, String path) {
        if (!tenant.enabled()) return Optional.empty();
        return Optional.of(new Resolution(new TenantContext(tenant, routing, scheme, authority, prefix), path));
    }

    private Optional<String> platformSubdomainSlug(String host) {
        for (String platform : platformHosts) {
            String suffix = "." + platform;
            if (host.endsWith(suffix)) {
                String label = host.substring(0, host.length() - suffix.length());
                if (Slugs.isValid(label)) return Optional.of(label);
            }
        }
        return Optional.empty();
    }

    private String effectiveAuthority(Request request) {
        if (trustForwardedHeaders && request.forwardedHost() != null && !request.forwardedHost().isBlank()) {
            String forwarded = request.forwardedHost().split(",")[0].trim();
            if (isKnownHost(forwarded)) return forwarded.toLowerCase(java.util.Locale.ROOT);
        }
        return request.host() == null ? "" : request.host().trim().toLowerCase(java.util.Locale.ROOT);
    }

    private String scheme(Request request) {
        if (publicScheme != null) return publicScheme;
        if (trustForwardedHeaders && request.forwardedProto() != null && !request.forwardedProto().isBlank()) {
            String proto = request.forwardedProto().split(",")[0].trim().toLowerCase(java.util.Locale.ROOT);
            if (proto.equals("https") || proto.equals("http")) return proto;
        }
        return request.scheme() == null ? "https" : request.scheme();
    }

    /** {@code /t/<slug>[/rest]} or {@code /.well-known/<name>/t/<slug>[/rest]}. */
    record PathTenant(String slug, String remainder) {

        static PathTenant parse(String path) {
            if (path.startsWith("/t/")) {
                String rest = path.substring(3);
                int slash = rest.indexOf('/');
                String slug = slash < 0 ? rest : rest.substring(0, slash);
                String remainder = slash < 0 ? "/" : rest.substring(slash);
                return Slugs.isValid(slug) ? new PathTenant(slug, remainder) : null;
            }
            if (path.startsWith("/.well-known/")) {
                String rest = path.substring("/.well-known/".length());
                int marker = rest.indexOf("/t/");
                if (marker <= 0) return null;
                String name = rest.substring(0, marker);
                if (name.contains("/")) return null;
                String afterMarker = rest.substring(marker + 3);
                int slash = afterMarker.indexOf('/');
                String slug = slash < 0 ? afterMarker : afterMarker.substring(0, slash);
                String tail = slash < 0 ? "" : afterMarker.substring(slash);
                return Slugs.isValid(slug) ? new PathTenant(slug, "/.well-known/" + name + tail) : null;
            }
            return null;
        }
    }
}
