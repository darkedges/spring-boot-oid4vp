package com.darkedges.oid4vp.verifier.jdbc;

import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpEphemeralEncryptionKeyRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpTransactionResultRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.Duration;

/**
 * The verifier's stores in PostgreSQL ({@code oid4vp.verifier.store.type=jdbc}, the application's {@code DataSource}): pending
 * requests, ephemeral response-encryption keys and same-device results, shared by every instance and kept across restarts.
 * Registered before the verifier's auto-configuration, whose in-memory stores back off.
 */
@AutoConfiguration(
        afterName = "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
        beforeName = "com.darkedges.oid4vp.spring.boot.autoconfigure.Oid4vpVerifierAutoConfiguration")
@ConditionalOnProperty(prefix = "oid4vp.verifier.store", name = "type", havingValue = "jdbc")
@EnableConfigurationProperties(Oid4vpVerifierJdbcAutoConfiguration.StoreProperties.class)
public class Oid4vpVerifierJdbcAutoConfiguration {

    /** {@code oid4vp.verifier.store.*}. */
    @ConfigurationProperties(prefix = "oid4vp.verifier.store")
    public static class StoreProperties {
        /** {@code jdbc} for PostgreSQL; otherwise in memory. */
        private String type = "memory";
        /** Base64 of 32 random bytes ({@code VERIFIER_STORE_ENCRYPTION_KEY}), required for jdbc: results hold verified identities. */
        private String encryptionKey;
        private boolean initializeSchema = true;
        /** How long a same-device result waits to be collected. */
        private Duration resultTtl = Duration.ofMinutes(10);

        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public String getEncryptionKey() { return encryptionKey; }
        public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }
        public boolean isInitializeSchema() { return initializeSchema; }
        public void setInitializeSchema(boolean initializeSchema) { this.initializeSchema = initializeSchema; }
        public Duration getResultTtl() { return resultTtl; }
        public void setResultTtl(Duration resultTtl) { this.resultTtl = resultTtl; }
    }

    @Bean
    @ConditionalOnMissingBean
    public VerifierEntryTable verifierEntryTable(ObjectProvider<DataSource> dataSource, StoreProperties properties) {
        DataSource ds = dataSource.getIfAvailable();
        if (ds == null) throw new IllegalStateException("oid4vp.verifier.store.type=jdbc needs a DataSource (spring.datasource.*)");
        if (properties.isInitializeSchema()) {
            new ResourceDatabasePopulator(new ClassPathResource("oid4vp-verifier-jdbc/schema-postgresql.sql")).execute(ds);
        }
        return VerifierEntryTable.create(JdbcClient.create(ds), properties.getEncryptionKey());
    }

    @Bean
    @ConditionalOnMissingBean
    public Oid4vpAuthorizationRequestRepository oid4vpAuthorizationRequestRepository(VerifierEntryTable table) {
        return new JdbcVerifierStores.AuthorizationRequests(table, Clock.systemUTC());
    }

    @Bean
    @ConditionalOnMissingBean
    public Oid4vpEphemeralEncryptionKeyRepository oid4vpEphemeralEncryptionKeyRepository(VerifierEntryTable table) {
        return new JdbcVerifierStores.EphemeralEncryptionKeys(table);
    }

    @Bean
    @ConditionalOnMissingBean
    public Oid4vpTransactionResultRepository oid4vpTransactionResultRepository(VerifierEntryTable table, StoreProperties properties) {
        return new JdbcVerifierStores.TransactionResults(table, Clock.systemUTC(), properties.getResultTtl());
    }
}
