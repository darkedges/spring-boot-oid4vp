package com.darkedges.oid4vp.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantContext;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.keys.TenantKey;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQueryReader;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.request.ClientMetadata;
import com.darkedges.oid4vp.core.request.ClientMetadataReader;
import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.darkedges.oid4vp.core.request.RequestUriMethod;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpIssuerTrust;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRegistrationKey;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpDcApiOriginPolicy;
import com.darkedges.oid4vp.spring.security.web.Oid4vpTenantResolver;
import com.darkedges.oid4vp.verifier.request.RequestObjectSigner;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;
import jakarta.servlet.http.HttpServletRequest;

import java.net.URI;
import java.net.http.HttpClient;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Makes a verifier serve every tenant of an {@code oid4vc-tenancy} deployment. The application keeps wiring
 * {@code Oid4vpLoginConfigurer} itself and passes each of its single-tenant pieces through this:
 * <pre>
 * .tenantResolver(tenancy.tenantResolver())
 * .relyingPartyRegistrationRepository(tenancy.registrations(registrations))
 * .requestObjectSigningKeyResolver(tenancy.requestObjectSigningKeys(signingKeys))
 * .issuerTrust(tenancy.issuerTrust(issuerKeyResolver))
 * .dcApiOriginPolicy(tenancy.dcApiOriginPolicy())
 * .walletInvocation(tenancy.url("/oid4vp/request", requestUriBase))
 * .sameDeviceHandoff(results, tenancy.url("/oid4vp/result", resultBaseUri))
 * </pre>
 *
 * <p>The deployment's default tenant is the verifier as it was: its registrations, keys and trust are the application's own, under
 * their plain ids. Every other tenant's come from its {@code settings} (see {@link TenantVerifierSettings}) and its own
 * {@code request-object} key, whose certificate gives it its own {@code x509_hash} client id.
 */
public final class Oid4vpTenancy {

    public static final String REQUEST_OBJECT_KEY = "request-object";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private record Built(Instant version, TenantVerifierSettings settings, IssuerKeyResolver trust) {}

    private final TenantRepository tenants;
    private final TenantKeyService keys;
    private final String defaultTenantId;
    private final String responsePath;
    private final HttpClient http;
    private final Clock clock;
    private final Map<String, Built> built = new ConcurrentHashMap<>();

    /**
     * @param defaultTenantId the deployment's default tenant ({@code oid4vc.tenancy.default-tenant.id}), served by the application's
     *                        own registrations; may be {@code null}
     * @param responsePath    where responses are posted, the registration id appended ({@code /login/oid4vp/direct-post/})
     */
    public Oid4vpTenancy(TenantRepository tenants, TenantKeyService keys, String defaultTenantId, String responsePath,
                         HttpClient http, Clock clock) {
        if (!keys.purposes().contains(REQUEST_OBJECT_KEY)) {
            throw new IllegalStateException("oid4vc.tenancy.keys.purposes must include \"" + REQUEST_OBJECT_KEY + "\" for a verifier");
        }
        this.tenants = tenants;
        this.keys = keys;
        this.defaultTenantId = defaultTenantId == null || defaultTenantId.isBlank() ? null : defaultTenantId;
        this.responsePath = responsePath.endsWith("/") ? responsePath : responsePath + "/";
        this.http = http;
        this.clock = clock;
    }

    /** The request's tenant: the default tenant is {@link Oid4vpRegistrationKey#DEFAULT_TENANT}, so its keys are plain ids. */
    public Oid4vpTenantResolver tenantResolver() {
        return request -> TenantContext.from(request)
                .map(context -> tenantKey(context.tenantId()))
                .orElse(Oid4vpRegistrationKey.DEFAULT_TENANT);
    }

    /** The key a tenant's registrations, requests and transactions are kept under. */
    public String tenantKey(String tenantId) {
        return tenantId.equals(defaultTenantId) ? Oid4vpRegistrationKey.DEFAULT_TENANT : tenantId;
    }

    private boolean isDefault(String key) {
        return Oid4vpRegistrationKey.DEFAULT_TENANT.equals(Oid4vpRegistrationKey.tenantOf(key));
    }

    /** The request parameters a tenant lets its backend add to this registration's transactions; none unless listed. */
    public Set<String> requestParameters(Tenant tenant, String registrationId) {
        if (tenant.id().equals(defaultTenantId)) return Set.of(); // the application's own registrations list none
        TenantVerifierSettings.Registration spec = built(tenant).settings().registrations().get(registrationId);
        return spec == null ? Set.of() : spec.requestParameters();
    }

    /** The key a registration of this request's tenant is known by. */
    public String registrationKey(String tenantId, String registrationId) {
        return Oid4vpRegistrationKey.of(tenantKey(tenantId), registrationId);
    }

    /** The application's registrations for the default tenant; each other tenant's from its settings, on the URL it was reached on. */
    public Oid4vpRelyingPartyRegistrationRepository registrations(Oid4vpRelyingPartyRegistrationRepository forDefaultTenant) {
        return key -> {
            if (isDefault(key)) return forDefaultTenant.findByRegistrationId(key);
            Optional<TenantContext> context = TenantContext.current().filter(c -> c.tenantId().equals(Oid4vpRegistrationKey.tenantOf(key)));
            if (context.isEmpty()) return Optional.empty(); // a tenant's registrations exist only on its own URLs
            Tenant tenant = context.get().tenant();
            String id = Oid4vpRegistrationKey.registrationIdOf(key);
            return Optional.ofNullable(built(tenant).settings().registrations().get(id))
                    .map(spec -> registration(key, id, spec, context.get(), tenant));
        };
    }

    private Oid4vpRelyingPartyRegistration registration(String key, String id, TenantVerifierSettings.Registration spec,
                                                        TenantContext context, Tenant tenant) {
        ClientIdentifierPrefix clientId = new ClientIdentifierPrefix.X509Hash(certificateHash(keys.activeKey(tenant, REQUEST_OBJECT_KEY)));
        DcqlQuery dcql = spec.dcqlQuery();
        return new Oid4vpRelyingPartyRegistration(key, clientId, URI.create(context.url(responsePath + id)), spec.responseMode(),
                () -> dcql, spec.clientMetadata(), spec.walletAuthorizationEndpoint(), List.of(), Optional.empty(), spec.requestUriMethod());
    }

    /** {@code x509_hash}: base64url SHA-256 of the DER certificate. */
    static String certificateHash(TenantKey key) {
        try {
            return Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(key.certificate().getEncoded())).toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The application's request-object signing key for the default tenant; each other tenant's own. */
    public RequestObjectSigningKeyResolver requestObjectSigningKeys(RequestObjectSigningKeyResolver forDefaultTenant) {
        return key -> {
            if (isDefault(key)) return forDefaultTenant == null ? Optional.empty() : forDefaultTenant.resolveSigningKey(key);
            return tenants.findById(Oid4vpRegistrationKey.tenantOf(key)).map(tenant -> {
                try {
                    return MAPPER.readTree(keys.activeKey(tenant, REQUEST_OBJECT_KEY).key().toJSONString());
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
        };
    }

    /** The application's issuer trust for the default tenant; each other tenant trusts only its {@code trustedIssuers}. */
    public Oid4vpIssuerTrust issuerTrust(IssuerKeyResolver forDefaultTenant) {
        IssuerKeyResolver none = (issuer, kid, chain) -> Optional.empty();
        return tenantKey -> {
            if (Oid4vpRegistrationKey.DEFAULT_TENANT.equals(tenantKey)) return forDefaultTenant;
            return tenants.findById(tenantKey).map(tenant -> built(tenant).trust()).orElse(none);
        };
    }

    /**
     * The default tenant accepts any origin, as before. Each other tenant accepts its own origin (the URL it was reached on) and the
     * origins its settings list in {@code dcApiAllowedOrigins}.
     */
    public Oid4vpDcApiOriginPolicy dcApiOriginPolicy() {
        return (request, key, origin) -> {
            if (isDefault(key)) return true;
            Optional<TenantContext> context = TenantContext.from(request);
            if (context.isEmpty()) return false;
            Set<String> allowed = built(context.get().tenant()).settings().dcApiAllowedOrigins();
            return origin.equals(context.get().origin()) || allowed.contains(origin);
        };
    }

    /**
     * A URL of the request's tenant, such as its {@code request_uri} base: {@code path} under the tenant's base URL, or
     * {@code defaultTenantUrl} for the default tenant.
     */
    public Function<HttpServletRequest, String> url(String path, String defaultTenantUrl) {
        return request -> TenantContext.from(request)
                .filter(context -> !context.tenantId().equals(defaultTenantId))
                .map(context -> context.url(path))
                .orElse(defaultTenantUrl);
    }

    private Built built(Tenant tenant) {
        Built current = built.get(tenant.id());
        if (current != null && current.version().equals(tenant.updatedAt())) return current;
        TenantVerifierSettings settings = TenantVerifierSettings.read(tenant.settings());
        Built fresh = new Built(tenant.updatedAt(), settings, new TrustListIssuerKeyResolver(settings.trustedIssuers(), http, clock));
        built.put(tenant.id(), fresh);
        return fresh;
    }

    /** A verifier's settings for a tenant. */
    public record TenantVerifierSettings(Map<String, Registration> registrations, List<TrustListIssuerKeyResolver.TrustedIssuer> trustedIssuers,
                                         Set<String> dcApiAllowedOrigins) {

        /**
         * One relying party:
         * <pre>
         * "registrations": { "login": { "dcqlQuery": {...}, "responseMode": "direct_post", "clientMetadata": {...},
         *                               "walletAuthorizationEndpoint": "openid4vp://", "requestUriMethod": "get",
         *                               "requestParameters": ["not_before"] } }
         * </pre>
         * {@code requestParameters} names what the tenant's backend may add to a transaction's request object.
         */
        public record Registration(DcqlQuery dcqlQuery, ResponseMode responseMode, Optional<ClientMetadata> clientMetadata,
                                   Optional<URI> walletAuthorizationEndpoint, RequestUriMethod requestUriMethod,
                                   Set<String> requestParameters) {}

        public static TenantVerifierSettings read(JsonNode settings) {
            Map<String, Registration> registrations = new java.util.LinkedHashMap<>();
            JsonNode specs = settings.path("registrations");
            specs.fieldNames().forEachRemaining(id -> {
                if (id.isBlank() || id.contains("/")) throw new IllegalArgumentException("not a registration id: " + id);
                JsonNode spec = specs.get(id);
                DcqlQuery dcql;
                try {
                    dcql = DcqlQueryReader.read(spec.path("dcqlQuery"));
                } catch (RuntimeException e) {
                    throw new IllegalArgumentException("registration \"" + id + "\": dcqlQuery is not valid DCQL (" + e.getMessage() + ")");
                }
                ResponseMode mode = ResponseMode.fromValue(spec.path("responseMode").asText("direct_post"));
                mode.requireImplemented();
                Optional<ClientMetadata> metadata = spec.hasNonNull("clientMetadata")
                        ? Optional.of(ClientMetadataReader.read(spec.get("clientMetadata"))) : Optional.empty();
                Optional<URI> wallet;
                try {
                    wallet = spec.hasNonNull("walletAuthorizationEndpoint")
                            ? Optional.of(new URI(spec.get("walletAuthorizationEndpoint").asText())) : Optional.empty();
                } catch (java.net.URISyntaxException e) {
                    throw new IllegalArgumentException("registration \"" + id + "\": walletAuthorizationEndpoint is not a URI (such as openid4vp://authorize)");
                }
                RequestUriMethod method = RequestUriMethod.parse(spec.path("requestUriMethod").asText("get"));
                registrations.put(id, new Registration(dcql, mode, metadata, wallet, method, requestParameterNames(id, spec)));
            });
            List<TrustListIssuerKeyResolver.TrustedIssuer> trusted = TrustListIssuerKeyResolver.read(settings.path("trustedIssuers"));
            Set<String> origins = new java.util.LinkedHashSet<>();
            for (JsonNode origin : settings.path("dcApiAllowedOrigins")) {
                URI uri = URI.create(origin.asText());
                if (uri.getScheme() == null || uri.getHost() == null || (uri.getPath() != null && !uri.getPath().isEmpty())) {
                    throw new IllegalArgumentException("not an origin: " + origin.asText());
                }
                origins.add(origin.asText());
            }
            return new TenantVerifierSettings(Map.copyOf(registrations), trusted, Set.copyOf(origins));
        }

        private static Set<String> requestParameterNames(String id, JsonNode spec) {
            JsonNode listed = spec.path("requestParameters");
            if (listed.isMissingNode() || listed.isNull()) return Set.of();
            if (!listed.isArray()) throw new IllegalArgumentException("registration \"" + id + "\": requestParameters is a list of names");
            Set<String> names = new java.util.LinkedHashSet<>();
            for (JsonNode entry : listed) {
                String name = entry.asText();
                // expires_at is the verifier's to set, from the transaction's lifetime.
                if (!entry.isTextual() || !name.matches("[a-z][a-z0-9_]{0,63}") || name.equals("expires_at")
                        || RequestObjectSigner.isReserved(name)) {
                    throw new IllegalArgumentException("registration \"" + id + "\": \"" + name + "\" can't be a request parameter");
                }
                names.add(name);
            }
            return Set.copyOf(names);
        }

        /** What's wrong with these settings, if anything: the console's admin API refuses to save them. */
        public static List<String> problems(JsonNode settings) {
            List<String> problems = new ArrayList<>();
            try {
                read(settings);
            } catch (RuntimeException e) {
                problems.add(e.getMessage() == null ? e.toString() : e.getMessage());
            }
            return problems;
        }
    }
}
