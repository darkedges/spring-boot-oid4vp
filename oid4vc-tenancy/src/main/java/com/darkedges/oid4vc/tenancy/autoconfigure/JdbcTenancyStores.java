package com.darkedges.oid4vc.tenancy.autoconfigure;

import com.darkedges.oid4vc.tenancy.JdbcTenantRepository;
import com.darkedges.oid4vc.tenancy.TenantRepository;
import com.darkedges.oid4vc.tenancy.keys.JdbcTenantKeyRepository;
import com.darkedges.oid4vc.tenancy.keys.KeyEncryptor;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyRepository;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;

/**
 * The PostgreSQL stores. Kept out of {@link TenancyAutoConfiguration} so that class loads without spring-jdbc and spring-tx, which
 * an application using the memory store need not have: this class is only loaded when {@code store.type=jdbc}.
 */
final class JdbcTenancyStores {

    private JdbcTenancyStores() {}

    static TenantRepository tenants(DataSource dataSource, boolean initializeSchema) {
        if (initializeSchema) {
            new ResourceDatabasePopulator(new ClassPathResource("oid4vc-tenancy/schema-postgresql.sql")).execute(dataSource);
        }
        return new JdbcTenantRepository(JdbcClient.create(dataSource));
    }

    static TenantKeyRepository keys(DataSource dataSource, KeyEncryptor encryptor) {
        return new JdbcTenantKeyRepository(JdbcClient.create(dataSource), encryptor,
                new TransactionTemplate(new DataSourceTransactionManager(dataSource)));
    }
}
