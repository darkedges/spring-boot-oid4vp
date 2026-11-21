package com.darkedges.oid4vc.tenancy.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * {@code oid4vc.tenancy.*}: makes an issuer or verifier deployment serve many tenants. Off unless {@code enabled=true}, so existing
 * single-tenant deployments are unchanged.
 */
@ConfigurationProperties(prefix = "oid4vc.tenancy")
public class TenancyProperties {

    private boolean enabled;

    /** {@code issuer} or {@code verifier}: which settings this deployment keeps, and the AuthStack domain purpose it serves. */
    private String service = "issuer";

    /**
     * The deployment's shared origins, such as {@code https://issuer.zkp.au}: tenants are served on {@code <slug>.<host>} and on
     * {@code <host>/t/<slug>}. In development, {@code http://localhost:8092}.
     */
    private List<URI> platformOrigins = new ArrayList<>();

    /** Paths served without a tenant on any host: the admin API, health checks, platform callbacks. */
    private List<String> platformPaths = new ArrayList<>(List.of("/admin/api/**", "/actuator/**", "/error"));

    /** Whether a proxy in front sets X-Forwarded-Host / -Proto (Cloudflare tunnel, ingress). */
    private boolean trustForwardedHeaders = true;

    /** Forces the scheme of every tenant URL (behind a TLS-terminating proxy that doesn't send X-Forwarded-Proto). */
    private String publicScheme;

    /** Custom domains configured by the operator, host to environment id (development, or set up by hand). */
    private Map<String, String> customDomains = new LinkedHashMap<>();

    private final DefaultTenant defaultTenant = new DefaultTenant();
    private final Store store = new Store();
    private final Keys keys = new Keys();
    private final AuthStack authstack = new AuthStack();
    private final Admin admin = new Admin();

    /** The tenant served on the platform origins themselves (no {@code /t/<slug>}): today's single-tenant deployment. */
    public static class DefaultTenant {
        /** Its id (an AuthStack environment id, or a name such as {@code zkp}); none when blank. */
        private String id;
        private String slug;
        private String organizationId;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getSlug() { return slug; }
        public void setSlug(String slug) { this.slug = slug; }
        public String getOrganizationId() { return organizationId; }
        public void setOrganizationId(String organizationId) { this.organizationId = organizationId; }
    }

    public static class Store {
        /** {@code jdbc} (PostgreSQL, the application's DataSource) or {@code memory} (tests, development: lost on restart). */
        private String type = "jdbc";
        /** Creates the tables at start-up if they don't exist. */
        private boolean initializeSchema = true;
        /** How long a tenant looked up is reused before it is read again (a change through another instance shows after this). */
        private Duration cacheTtl = Duration.ofSeconds(15);

        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public boolean isInitializeSchema() { return initializeSchema; }
        public void setInitializeSchema(boolean initializeSchema) { this.initializeSchema = initializeSchema; }
        public Duration getCacheTtl() { return cacheTtl; }
        public void setCacheTtl(Duration cacheTtl) { this.cacheTtl = cacheTtl; }
    }

    public static class Keys {
        /** Base64 of 32 random bytes ({@code TENANT_KEY_ENCRYPTION_KEY}). Required for the jdbc store. Losing it loses every key. */
        private String encryptionKey;
        /** The purposes keys exist for. */
        private Set<String> purposes = new LinkedHashSet<>(List.of("issuer-signing", "mdoc", "request-object"));
        /** PKCS#12 keystore holding the CA that issues tenant certificates; self-signed certificates without one. */
        private String caKeystore;
        private String caKeystorePassword;
        private String caAlias;
        private Duration certificateValidity = Duration.ofDays(365);

        public String getEncryptionKey() { return encryptionKey; }
        public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }
        public Set<String> getPurposes() { return purposes; }
        public void setPurposes(Set<String> purposes) { this.purposes = purposes; }
        public String getCaKeystore() { return caKeystore; }
        public void setCaKeystore(String caKeystore) { this.caKeystore = caKeystore; }
        public String getCaKeystorePassword() { return caKeystorePassword; }
        public void setCaKeystorePassword(String caKeystorePassword) { this.caKeystorePassword = caKeystorePassword; }
        public String getCaAlias() { return caAlias; }
        public void setCaAlias(String caAlias) { this.caAlias = caAlias; }
        public Duration getCertificateValidity() { return certificateValidity; }
        public void setCertificateValidity(Duration certificateValidity) { this.certificateValidity = certificateValidity; }
    }

    /** AuthStack: who console users are, and which custom domains are verified. */
    public static class AuthStack {
        /** AuthStack's console API, for {@code /api/auth/me} and {@code /api/platform/domains}. */
        private URI apiUrl;
        /** The platform worker's token endpoint and credentials, for the domain directory. No domain directory without them. */
        private URI tokenUrl;
        private String clientId;
        private String clientSecret;
        private Duration domainRefresh = Duration.ofSeconds(30);
        private Duration domainMissBackoff = Duration.ofSeconds(5);

        public URI getApiUrl() { return apiUrl; }
        public void setApiUrl(URI apiUrl) { this.apiUrl = apiUrl; }
        public URI getTokenUrl() { return tokenUrl; }
        public void setTokenUrl(URI tokenUrl) { this.tokenUrl = tokenUrl; }
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
        public Duration getDomainRefresh() { return domainRefresh; }
        public void setDomainRefresh(Duration domainRefresh) { this.domainRefresh = domainRefresh; }
        public Duration getDomainMissBackoff() { return domainMissBackoff; }
        public void setDomainMissBackoff(Duration domainMissBackoff) { this.domainMissBackoff = domainMissBackoff; }
    }

    public static class Admin {
        private boolean enabled = true;
        /** Origins allowed to call the admin API from a browser: the AuthStack console. */
        private List<String> allowedOrigins = new ArrayList<>();

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public List<String> getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getService() { return service; }
    public void setService(String service) { this.service = service; }
    public List<URI> getPlatformOrigins() { return platformOrigins; }
    public void setPlatformOrigins(List<URI> platformOrigins) { this.platformOrigins = platformOrigins; }
    public List<String> getPlatformPaths() { return platformPaths; }
    public void setPlatformPaths(List<String> platformPaths) { this.platformPaths = platformPaths; }
    public boolean isTrustForwardedHeaders() { return trustForwardedHeaders; }
    public void setTrustForwardedHeaders(boolean trustForwardedHeaders) { this.trustForwardedHeaders = trustForwardedHeaders; }
    public String getPublicScheme() { return publicScheme; }
    public void setPublicScheme(String publicScheme) { this.publicScheme = publicScheme; }
    public Map<String, String> getCustomDomains() { return customDomains; }
    public void setCustomDomains(Map<String, String> customDomains) { this.customDomains = customDomains; }
    public DefaultTenant getDefaultTenant() { return defaultTenant; }
    public Store getStore() { return store; }
    public Keys getKeys() { return keys; }
    public AuthStack getAuthstack() { return authstack; }
    public Admin getAdmin() { return admin; }
}
