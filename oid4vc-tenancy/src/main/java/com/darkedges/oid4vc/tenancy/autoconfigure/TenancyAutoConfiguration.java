package com.darkedges.oid4vc.tenancy.autoconfigure;

import com.darkedges.oid4vc.tenancy.CachingTenantRepository;
import com.darkedges.oid4vc.tenancy.InMemoryTenantRepository;
import com.darkedges.oid4vc.tenancy.JdbcTenantRepository;
import com.darkedges.oid4vc.tenancy.Slugs;
import com.darkedges.oid4vc.tenancy.Tenant;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.TenantResolver;
import com.darkedges.oid4vc.tenancy.admin.AuthStackConsoleAccounts;
import com.darkedges.oid4vc.tenancy.admin.ConsoleAccounts;
import com.darkedges.oid4vc.tenancy.admin.TenantAdminController;
import com.darkedges.oid4vc.tenancy.admin.TenantAdministration;
import com.darkedges.oid4vc.tenancy.admin.TenantSettingsValidator;
import com.darkedges.oid4vc.tenancy.domains.AuthStackDomainDirectory;
import com.darkedges.oid4vc.tenancy.domains.DomainDirectory;
import com.darkedges.oid4vc.tenancy.domains.StaticDomainDirectory;
import com.darkedges.oid4vc.tenancy.keys.InMemoryTenantKeyRepository;
import com.darkedges.oid4vc.tenancy.keys.JdbcTenantKeyRepository;
import com.darkedges.oid4vc.tenancy.keys.KeyEncryptor;
import com.darkedges.oid4vc.tenancy.keys.TenantCertificateAuthority;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyRepository;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.darkedges.oid4vc.tenancy.web.TenantResolutionFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.sql.DataSource;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Multi-tenancy for an issuer or verifier, when {@code oid4vc.tenancy.enabled=true}: the tenant and key stores, the tenant resolver
 * and its servlet filter (ahead of Spring Security), and the admin API for the AuthStack console.
 */
@AutoConfiguration(afterName = "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration")
@ConditionalOnBooleanProperty(name = "oid4vc.tenancy.enabled")
@EnableConfigurationProperties(TenancyProperties.class)
public class TenancyAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(TenancyAutoConfiguration.class);

    /** Runs before Spring Security's filter chain (order -100), so security rules see the tenant and the stripped path. */
    public static final int FILTER_ORDER = Ordered.HIGHEST_PRECEDENCE + 50;

    @Bean
    @ConditionalOnMissingBean
    public TenantRepository tenantRepository(TenancyProperties properties, ObjectProvider<DataSource> dataSource) {
        TenantRepository store = isJdbc(properties)
                ? new JdbcTenantRepository(JdbcClient.create(requireDataSource(dataSource, properties)))
                : new InMemoryTenantRepository();
        if (isJdbc(properties) && properties.getStore().isInitializeSchema()) {
            new ResourceDatabasePopulator(new ClassPathResource("oid4vc-tenancy/schema-postgresql.sql"))
                    .execute(requireDataSource(dataSource, properties));
        }
        TenantRepository cached = new CachingTenantRepository(store, properties.getStore().getCacheTtl());
        bootstrapDefaultTenant(cached, properties.getDefaultTenant());
        return cached;
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantKeyRepository tenantKeyRepository(TenancyProperties properties, ObjectProvider<DataSource> dataSource,
                                                   TenantRepository tenants /* tables created first */) {
        if (!isJdbc(properties)) {
            log.warn("oid4vc.tenancy keys are kept in memory: every tenant key is lost on restart");
            return new InMemoryTenantKeyRepository();
        }
        DataSource ds = requireDataSource(dataSource, properties);
        return new JdbcTenantKeyRepository(JdbcClient.create(ds), KeyEncryptor.fromBase64(properties.getKeys().getEncryptionKey()),
                new TransactionTemplate(new DataSourceTransactionManager(ds)));
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantCertificateAuthority tenantCertificateAuthority(TenancyProperties properties) throws Exception {
        TenancyProperties.Keys keys = properties.getKeys();
        if (keys.getCaKeystore() == null || keys.getCaKeystore().isBlank()) {
            log.warn("oid4vc.tenancy.keys.ca-keystore is not set: tenant keys get self-signed certificates, which wallets and verifiers won't trust");
            return TenantCertificateAuthority.selfSigned(keys.getCertificateValidity());
        }
        try (InputStream in = new DefaultResourceLoader().getResource(keys.getCaKeystore()).getInputStream()) {
            char[] password = keys.getCaKeystorePassword() == null ? new char[0] : keys.getCaKeystorePassword().toCharArray();
            return TenantCertificateAuthority.fromKeyStore(in, password, keys.getCaAlias(), keys.getCertificateValidity());
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantKeyService tenantKeyService(TenantKeyRepository keys, TenantCertificateAuthority authority, TenancyProperties properties) {
        return new TenantKeyService(keys, authority, properties.getKeys().getPurposes());
    }

    @Bean
    @ConditionalOnMissingBean
    public DomainDirectory domainDirectory(TenancyProperties properties) {
        List<DomainDirectory> directories = new ArrayList<>();
        if (!properties.getCustomDomains().isEmpty()) directories.add(new StaticDomainDirectory(properties.getCustomDomains()));
        TenancyProperties.AuthStack authstack = properties.getAuthstack();
        if (authstack.getApiUrl() != null && authstack.getTokenUrl() != null && authstack.getClientId() != null
                && authstack.getClientSecret() != null) {
            directories.add(new AuthStackDomainDirectory(authstack.getApiUrl(), properties.getService(), authstack.getTokenUrl(),
                    authstack.getClientId(), authstack.getClientSecret(), authstack.getDomainRefresh(), authstack.getDomainMissBackoff(),
                    HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(), Clock.systemUTC()));
        } else {
            log.info("No AuthStack platform worker configured: tenants are served on platform subdomains and paths only");
        }
        return directories.isEmpty() ? DomainDirectory.NONE : StaticDomainDirectory.firstOf(directories);
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantResolver tenantResolver(TenantRepository tenants, DomainDirectory domains, TenancyProperties properties) {
        List<String> hosts = properties.getPlatformOrigins().stream().map(URI::getHost).toList();
        if (hosts.isEmpty()) throw new IllegalStateException("oid4vc.tenancy.platform-origins is empty: name at least the deployment's own origin");
        String defaultId = properties.getDefaultTenant().getId();
        return new TenantResolver(tenants, domains, hosts, defaultId, properties.isTrustForwardedHeaders(), properties.getPublicScheme());
    }

    @Bean
    public FilterRegistrationBean<TenantResolutionFilter> tenantResolutionFilter(TenantResolver resolver, TenancyProperties properties) {
        FilterRegistrationBean<TenantResolutionFilter> registration =
                new FilterRegistrationBean<>(new TenantResolutionFilter(resolver, properties.getPlatformPaths()));
        registration.setOrder(FILTER_ORDER);
        registration.addUrlPatterns("/*");
        return registration;
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(WebMvcConfigurer.class)
    @ConditionalOnBooleanProperty(name = "oid4vc.tenancy.admin.enabled", matchIfMissing = true)
    static class AdminApi {

        @Bean
        @ConditionalOnMissingBean
        TenantSettingsValidator tenantSettingsValidator() {
            return TenantSettingsValidator.ANY;
        }

        @Bean
        @ConditionalOnMissingBean
        ConsoleAccounts consoleAccounts(TenancyProperties properties) {
            URI api = properties.getAuthstack().getApiUrl();
            if (api == null) throw new IllegalStateException("oid4vc.tenancy.authstack.api-url is required for the admin API (or set oid4vc.tenancy.admin.enabled=false)");
            return new AuthStackConsoleAccounts(api, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(), Clock.systemUTC());
        }

        @Bean
        @ConditionalOnMissingBean
        TenantAdministration tenantAdministration(TenantRepository tenants, TenantKeyService keys, TenantSettingsValidator validator,
                                                  TenancyProperties properties) {
            return new TenantAdministration(tenants, keys, validator, properties.getPlatformOrigins(), properties.getService());
        }

        @Bean
        TenantAdminController tenantAdminController(TenantAdministration administration, ConsoleAccounts accounts) {
            return new TenantAdminController(administration, accounts);
        }

        @Bean
        WebMvcConfigurer tenantAdminCors(TenancyProperties properties) {
            List<String> origins = properties.getAdmin().getAllowedOrigins();
            return new WebMvcConfigurer() {
                @Override
                public void addCorsMappings(CorsRegistry registry) {
                    if (origins.isEmpty()) return;
                    registry.addMapping("/admin/api/**").allowedOrigins(origins.toArray(String[]::new))
                            .allowedMethods("GET", "PUT", "POST", "DELETE").allowedHeaders("Authorization", "Content-Type").maxAge(600);
                }
            };
        }
    }

    private static boolean isJdbc(TenancyProperties properties) {
        return "jdbc".equalsIgnoreCase(properties.getStore().getType());
    }

    private static DataSource requireDataSource(ObjectProvider<DataSource> dataSource, TenancyProperties properties) {
        DataSource ds = dataSource.getIfAvailable();
        if (ds == null) throw new IllegalStateException("oid4vc.tenancy.store.type=jdbc needs a DataSource (spring.datasource.*), or set it to memory");
        return ds;
    }

    private static void bootstrapDefaultTenant(TenantRepository tenants, TenancyProperties.DefaultTenant configured) {
        if (configured.getId() == null || configured.getId().isBlank()) return;
        if (tenants.findById(configured.getId()).isPresent()) return;
        String slug = configured.getSlug() != null ? configured.getSlug() : configured.getId().toLowerCase();
        Slugs.requireValid(slug);
        tenants.save(Tenant.create(configured.getId(), configured.getOrganizationId(), slug));
        log.info("Created the default tenant {} ({})", configured.getId(), slug);
    }
}
