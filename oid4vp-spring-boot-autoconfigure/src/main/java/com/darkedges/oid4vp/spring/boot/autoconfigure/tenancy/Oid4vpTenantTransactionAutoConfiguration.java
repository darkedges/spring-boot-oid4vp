package com.darkedges.oid4vp.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.tenantapi.TenantCallers;
import com.darkedges.oid4vp.spring.boot.autoconfigure.Oid4vpVerifierAutoConfiguration;
import com.darkedges.oid4vp.spring.security.transaction.Oid4vpTransactionStore;
import com.darkedges.oid4vp.spring.security.transaction.Oid4vpTransactions;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

import java.time.Clock;
import java.time.Duration;

/**
 * Presentations a tenant's backend asks for ({@code /tenant-api/v1/transactions}), in a multi-tenant web verifier. The application
 * wires the other half into its security: {@code Oid4vpLoginConfigurer.transactions(...)}, and lets {@code /tenant-api/**} through
 * (the API checks the caller's token itself).
 */
@AutoConfiguration(
        after = {Oid4vpVerifierAutoConfiguration.class, Oid4vpVerifierTenancyAutoConfiguration.class},
        afterName = "com.darkedges.oid4vc.tenancy.autoconfigure.TenancyAutoConfiguration")
@ConditionalOnClass(name = {"com.darkedges.oid4vc.tenancy.tenantapi.TenantCallers", "org.springframework.web.bind.annotation.RestController"})
@ConditionalOnBooleanProperty(name = "oid4vc.tenancy.enabled")
@ConditionalOnBean({Oid4vpTenancy.class, TenantCallers.class, Oid4vpTransactionStore.class, Oid4vpAuthorizationRequestService.class})
public class Oid4vpTenantTransactionAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public Oid4vpTransactions oid4vpTransactions(Oid4vpTransactionStore store, Oid4vpAuthorizationRequestService requests,
                                                 Environment environment) {
        return new Oid4vpTransactions(store, requests, Clock.systemUTC(),
                environment.getProperty("oid4vp.verifier.tenancy.transaction-result-ttl", Duration.class, Duration.ofMinutes(10)));
    }

    @Bean
    @ConditionalOnMissingBean
    public TenantTransactionController tenantTransactionController(TenantCallers callers, Oid4vpTransactions transactions,
                                                                   Oid4vpTenancy tenancy) {
        return new TenantTransactionController(callers, transactions, tenancy);
    }
}
