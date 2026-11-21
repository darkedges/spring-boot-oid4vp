package com.darkedges.oid4vc.tenancy;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** A tenant's platform slug: one DNS label (it becomes {@code <slug>.<platform host>}), and not a reserved word. */
public final class Slugs {

    private static final Pattern LABEL = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");

    /** Labels that name the platform's own hosts or could mislead a person reading a URL. */
    public static final Set<String> RESERVED = Set.of(
            "www", "admin", "api", "app", "auth", "login", "console", "platform", "status", "static", "assets", "cdn", "mail",
            "customers", "default", "t", "well-known", "issuer", "verifier", "wallet", "authstack", "support", "help", "docs");

    private Slugs() {}

    public static boolean isValid(String slug) {
        return slug != null && LABEL.matcher(slug).matches() && !slug.startsWith("xn--");
    }

    /** Valid and not reserved: what a tenant may newly choose. A deployment's built-in tenant may use a reserved one. */
    public static boolean isAvailableForTenants(String slug) {
        return isValid(slug) && !RESERVED.contains(slug);
    }

    public static String requireValid(String slug) {
        if (!isValid(slug)) {
            throw new IllegalArgumentException("a slug is one lower-case DNS label (a-z, 0-9 and '-', at most 63): " + slug);
        }
        return slug;
    }

    /** Lower-cased, without a trailing dot or a port: how hosts are compared. */
    public static String normalizeHost(String host) {
        if (host == null) return "";
        String h = host.trim().toLowerCase(Locale.ROOT);
        if (h.startsWith("[")) {
            int end = h.indexOf(']');
            return end > 0 ? h.substring(0, end + 1) : h;
        }
        int colon = h.lastIndexOf(':');
        if (colon >= 0 && h.indexOf(':') == colon) h = h.substring(0, colon);
        while (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        return h;
    }
}
