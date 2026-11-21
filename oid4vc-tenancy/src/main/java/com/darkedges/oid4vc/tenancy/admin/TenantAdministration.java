package com.darkedges.oid4vc.tenancy.admin;

import com.darkedges.oid4vc.tenancy.Slugs;
import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.TenantSecrets;
import com.darkedges.oid4vc.tenancy.keys.TenantKey;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.util.Base64URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * What the AuthStack console can do with this service's tenants, one per environment. The rules:
 * <ul>
 *   <li>A platform administrator may manage every tenant.</li>
 *   <li>An organization administrator may manage the tenants of the environments their organization owns (as AuthStack lists them),
 *       and create one for such an environment. A viewer may only look.</li>
 *   <li>Anyone else is told the tenant doesn't exist (404), so tenant ids can't be probed.</li>
 *   <li>Secrets in the settings are write-only.</li>
 * </ul>
 */
public final class TenantAdministration {

    private static final Logger audit = LoggerFactory.getLogger("oid4vc.tenancy.audit");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int MAX_SETTINGS_BYTES = 64 * 1024;

    /** An answer for the console: an HTTP status and its JSON body. */
    public record Answer(int status, JsonNode body) {}

    private final TenantRepository tenants;
    private final TenantKeyService keys;
    private final TenantSettingsValidator validator;
    private final List<URI> platformOrigins;
    private final String service;

    /**
     * @param platformOrigins the deployment's shared origins, such as {@code https://issuer.zkp.au}, for showing a tenant's URLs
     * @param service         {@code issuer} or {@code verifier}: shown to the console, and the settings this service keeps
     */
    public TenantAdministration(TenantRepository tenants, TenantKeyService keys, TenantSettingsValidator validator,
                                List<URI> platformOrigins, String service) {
        this.tenants = tenants;
        this.keys = keys;
        this.validator = validator;
        this.platformOrigins = List.copyOf(platformOrigins);
        this.service = service;
    }

    public Answer list(ConsoleAccount account) {
        ArrayNode items = MAPPER.createArrayNode();
        for (Tenant tenant : tenants.findAll()) {
            if (account.mayRead(tenant.id(), tenant.organizationId())) items.add(summary(tenant));
        }
        ObjectNode body = MAPPER.createObjectNode().put("service", service);
        body.set("tenants", items);
        return new Answer(200, body);
    }

    public Answer get(ConsoleAccount account, String environmentId) {
        Optional<Tenant> tenant = tenants.findById(environmentId);
        if (!account.mayRead(environmentId, tenant.map(Tenant::organizationId).orElse(null))) return notFound();
        if (tenant.isEmpty()) return new Answer(404, error("not_configured", "This environment has not enabled " + service + " yet"));
        return new Answer(200, view(tenant.get()));
    }

    /**
     * Creates or changes the environment's tenant. Body: {@code slug}, {@code enabled}, {@code settings}, each optional. A new tenant's
     * slug defaults to its environment's name.
     */
    public Answer put(ConsoleAccount account, String environmentId, JsonNode body) {
        Optional<Tenant> existing = tenants.findById(environmentId);
        String owner = existing.map(Tenant::organizationId).orElse(null);
        if (!account.mayRead(environmentId, owner)) return notFound();
        if (!account.mayWrite(environmentId, owner)) return new Answer(403, error("forbidden", "Viewers can't change settings"));
        if (body == null || !body.isObject()) return badRequest("The body must be a JSON object");
        if (existing.isEmpty() && !account.isPlatformAdmin() && !account.environments().containsKey(environmentId)) return notFound();

        Tenant tenant = existing.orElse(null);
        String slug = body.hasNonNull("slug") ? body.get("slug").asText().trim().toLowerCase(Locale.ROOT) : null;
        if (tenant == null) {
            if (slug == null) slug = defaultSlug(account.environments().getOrDefault(environmentId, environmentId), environmentId);
            if (!Slugs.isAvailableForTenants(slug)) return badRequest("\"" + slug + "\" can't be used as a slug: one DNS label, not a reserved word");
            String organizationId = account.isPlatformAdmin() ? textOrNull(body, "organizationId") : account.organizationId();
            tenant = Tenant.create(environmentId, organizationId, slug);
        } else if (slug != null && !slug.equals(tenant.slug())) {
            if (!Slugs.isAvailableForTenants(slug)) return badRequest("\"" + slug + "\" can't be used as a slug: one DNS label, not a reserved word");
            tenant = tenant.withSlug(slug);
        }
        if (body.has("enabled")) {
            if (!body.get("enabled").isBoolean()) return badRequest("\"enabled\" is true or false");
            tenant = tenant.withEnabled(body.get("enabled").asBoolean());
        }
        if (body.has("settings")) {
            if (!body.get("settings").isObject()) return badRequest("\"settings\" must be an object");
            if (body.get("settings").toString().length() > MAX_SETTINGS_BYTES) return badRequest("The settings are larger than 64 KB");
            ObjectNode merged;
            try {
                merged = TenantSecrets.merge(tenant.settings(), (ObjectNode) body.get("settings"));
            } catch (IllegalArgumentException e) {
                return badRequest(e.getMessage());
            }
            List<String> problems = validator.validate(merged);
            if (!problems.isEmpty()) {
                ObjectNode answer = error("invalid_settings", "The settings were not saved");
                problems.forEach(answer.putArray("problems")::add);
                return new Answer(400, answer);
            }
            tenant = tenant.withSettings(merged);
        }
        try {
            tenant = tenants.save(tenant);
        } catch (TenantRepository.SlugTakenException e) {
            return new Answer(409, error("slug_taken", e.getMessage()));
        }
        audit.info("{} {} tenant {} ({}) by {}", existing.isEmpty() ? "created" : "updated", service, tenant.id(), tenant.slug(), account.who());
        return new Answer(existing.isEmpty() ? 201 : 200, view(tenant));
    }

    public Answer rotate(ConsoleAccount account, String environmentId, String purpose) {
        Optional<Tenant> tenant = writable(account, environmentId);
        if (tenant == null) return new Answer(403, error("forbidden", "Viewers can't rotate keys"));
        if (tenant.isEmpty()) return notFound();
        if (!keys.purposes().contains(purpose)) return badRequest("Unknown key purpose: " + purpose);
        TenantKey replacement = keys.rotate(tenant.get(), purpose);
        audit.info("rotated {} key of {} tenant {}: now {} by {}", purpose, service, environmentId, replacement.kid(), account.who());
        return new Answer(200, view(tenant.get()));
    }

    public Answer removeRetiredKey(ConsoleAccount account, String environmentId, String kid) {
        Optional<Tenant> tenant = writable(account, environmentId);
        if (tenant == null) return new Answer(403, error("forbidden", "Viewers can't remove keys"));
        if (tenant.isEmpty()) return notFound();
        if (!keys.removeRetired(tenant.get(), kid)) return new Answer(409, error("not_retired", "Only a retired key can be removed"));
        audit.info("removed retired key {} of {} tenant {} by {}", kid, service, environmentId, account.who());
        return new Answer(200, view(tenant.get()));
    }

    /** {@code null}: may see but not change; empty: not found or not theirs. */
    private Optional<Tenant> writable(ConsoleAccount account, String environmentId) {
        Optional<Tenant> tenant = tenants.findById(environmentId);
        String owner = tenant.map(Tenant::organizationId).orElse(null);
        if (!account.mayRead(environmentId, owner)) return Optional.empty();
        if (!account.mayWrite(environmentId, owner)) return null;
        return tenant;
    }

    private ObjectNode summary(Tenant tenant) {
        ObjectNode node = MAPPER.createObjectNode()
                .put("id", tenant.id())
                .put("slug", tenant.slug())
                .put("enabled", tenant.enabled())
                .put("updatedAt", tenant.updatedAt().toString());
        if (tenant.organizationId() != null) node.put("organizationId", tenant.organizationId());
        return node;
    }

    private ObjectNode view(Tenant tenant) {
        ObjectNode node = summary(tenant);
        node.put("service", service);
        node.set("settings", TenantSecrets.redact(tenant.settings()));
        ArrayNode urls = node.putArray("urls");
        for (URI origin : platformOrigins) {
            String port = origin.getPort() < 0 ? "" : ":" + origin.getPort();
            urls.addObject().put("routing", "PLATFORM_SUBDOMAIN").put("url", origin.getScheme() + "://" + tenant.slug() + "." + origin.getHost() + port);
            urls.addObject().put("routing", "PATH").put("url", origin.getScheme() + "://" + origin.getHost() + port + "/t/" + tenant.slug());
        }
        ArrayNode keyList = node.putArray("keys");
        for (TenantKey key : keys.allKeys(tenant)) {
            ObjectNode k = keyList.addObject()
                    .put("kid", key.kid())
                    .put("purpose", key.purpose())
                    .put("status", key.status().name())
                    .put("createdAt", key.createdAt().toString());
            if (key.retiredAt() != null) k.put("retiredAt", key.retiredAt().toString());
            X509Certificate certificate = key.certificate();
            k.putObject("certificate")
                    .put("subject", certificate.getSubjectX500Principal().getName())
                    .put("issuer", certificate.getIssuerX500Principal().getName())
                    .put("notAfter", certificate.getNotAfter().toInstant().toString())
                    .put("sha256", thumbprint(certificate));
        }
        keys.authority().caCertificate().ifPresent(ca -> node.putObject("certificateAuthority")
                .put("subject", ca.getSubjectX500Principal().getName())
                .put("sha256", thumbprint(ca))
                .put("pem", pem(ca)));
        return node;
    }

    static String defaultSlug(String environmentName, String environmentId) {
        String slug = environmentName.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("^-+|-+$", "");
        if (slug.length() > 40) slug = slug.substring(0, 40).replaceAll("-+$", "");
        if (Slugs.isAvailableForTenants(slug)) return slug;
        String fromId = environmentId.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        return "env-" + fromId.substring(0, Math.min(12, fromId.length()));
    }

    private static String thumbprint(X509Certificate certificate) {
        try {
            return Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())).toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String pem(X509Certificate certificate) {
        try {
            return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String textOrNull(JsonNode body, String field) {
        return body.hasNonNull(field) ? body.get(field).asText() : null;
    }

    private static Answer notFound() {
        return new Answer(404, error("not_found", "No such tenant"));
    }

    private static Answer badRequest(String message) {
        return new Answer(400, error("invalid_request", message));
    }

    private static ObjectNode error(String code, String description) {
        return MAPPER.createObjectNode().put("error", code).put("error_description", description);
    }
}
