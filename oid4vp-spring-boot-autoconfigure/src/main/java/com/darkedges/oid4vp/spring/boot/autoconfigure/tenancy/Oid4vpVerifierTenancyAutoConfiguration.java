package com.darkedges.oid4vp.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.admin.TenantSettingsValidator;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationResponseAuthenticationFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;

/**
 * The {@link Oid4vpTenancy} a multi-tenant verifier wires its {@code Oid4vpLoginConfigurer} through
 * ({@code oid4vc.tenancy.enabled=true}), and the validation of verifier settings the console saves. Registered before the tenancy
 * auto-configuration, so its admin API uses the verifier's settings validator.
 */
@AutoConfiguration(beforeName = "com.darkedges.oid4vc.tenancy.autoconfigure.TenancyAutoConfiguration")
@ConditionalOnClass(TenantKeyService.class)
@ConditionalOnBooleanProperty(name = "oid4vc.tenancy.enabled")
public class Oid4vpVerifierTenancyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Oid4vpTenancy oid4vpTenancy(TenantRepository tenants, TenantKeyService keys, Environment environment) {
        // The response path is the default /login/oid4vp/direct-post/{registrationId}, without the variable.
        String responsePath = Oid4vpAuthorizationResponseAuthenticationFilter.DEFAULT_RESPONSE_URI_PATTERN.replace("{registrationId}", "");
        return new Oid4vpTenancy(tenants, keys, environment.getProperty("oid4vc.tenancy.default-tenant.id"),
                environment.getProperty("oid4vp.verifier.tenancy.response-path", responsePath),
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(), Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantSettingsValidator tenantSettingsValidator() {
        return Oid4vpTenancy.TenantVerifierSettings::problems;
    }
}
