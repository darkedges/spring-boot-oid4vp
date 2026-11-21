package com.darkedges.oid4vc.tenancy;

import com.darkedges.oid4vc.tenancy.keys.JdbcTenantKeyRepository;
import com.darkedges.oid4vc.tenancy.keys.KeyEncryptor;
import com.darkedges.oid4vc.tenancy.keys.TenantKey;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The PostgreSQL stores against a real PostgreSQL: set {@code OID4VC_TEST_POSTGRES_URL} (for example
 * {@code jdbc:postgresql://localhost:55432/tenancy?user=tenancy&password=tenancy}). Skipped otherwise.
 */
@EnabledIfEnvironmentVariable(named = "OID4VC_TEST_POSTGRES_URL", matches = ".+")
class JdbcStoresTest {

    private DriverManagerDataSource dataSource;
    private JdbcClient jdbc;

    @BeforeEach
    void setUp() {
        dataSource = new DriverManagerDataSource(System.getenv("OID4VC_TEST_POSTGRES_URL"));
        jdbc = JdbcClient.create(dataSource);
        jdbc.sql("DROP TABLE IF EXISTS oid4vc_tenant_key, oid4vc_tenant").update();
        ResourceDatabasePopulator schema = new ResourceDatabasePopulator(new ClassPathResource("oid4vc-tenancy/schema-postgresql.sql"));
        schema.execute(dataSource);
        schema.execute(dataSource); // idempotent
    }

    @Test
    void tenantsAreStoredWithTheirSettingsAndUniqueSlugs() throws Exception {
        JdbcTenantRepository tenants = new JdbcTenantRepository(jdbc);
        Tenant bank = Tenant.create("env-bank", "org-1", "bank").withSettings(
                (com.fasterxml.jackson.databind.node.ObjectNode) new com.fasterxml.jackson.databind.ObjectMapper().readTree("{\"a\":{\"b\":[1,2]}}"));
        tenants.save(bank);
        tenants.save(Tenant.create("env-shop", "org-2", "shop"));

        Tenant loaded = tenants.findBySlug("bank").orElseThrow();
        assertThat(loaded.id()).isEqualTo("env-bank");
        assertThat(loaded.settings().path("a").path("b").get(1).asInt()).isEqualTo(2);
        assertThat(tenants.findAll()).extracting(Tenant::slug).containsExactly("bank", "shop");

        tenants.save(loaded.withEnabled(false));
        assertThat(tenants.findById("env-bank").orElseThrow().enabled()).isFalse();

        assertThatThrownBy(() -> tenants.save(Tenant.create("env-x", "org-3", "shop"))).isInstanceOf(TenantRepository.SlugTakenException.class);
        assertThat(tenants.delete("env-shop")).isTrue();
        assertThat(tenants.findBySlug("shop")).isEmpty();
    }

    @Test
    void keysAreStoredEncryptedRotatedAndRemovedWithTheirTenant() throws Exception {
        JdbcTenantRepository tenants = new JdbcTenantRepository(jdbc);
        Tenant bank = tenants.save(Tenant.create("env-bank", "org-1", "bank"));
        KeyEncryptor encryptor = KeyEncryptor.ephemeral();
        var repository = new JdbcTenantKeyRepository(jdbc, encryptor, new TransactionTemplate(new DataSourceTransactionManager(dataSource)));
        TenantKeyService keys = new TenantKeyService(repository, TenantKeysTest.testCa(), Set.of("issuer-signing"));

        TenantKey first = keys.activeKey(bank, "issuer-signing");
        TenantKey reloaded = keys.activeKey(bank, "issuer-signing");
        assertThat(reloaded.kid()).isEqualTo(first.kid());
        assertThat(reloaded.key().toECPrivateKey().getS()).isEqualTo(first.key().toECPrivateKey().getS());
        assertThat(reloaded.x5c()).hasSize(1);

        // Nothing private is stored in the clear.
        String d = first.key().getD().toString();
        Integer clear = jdbc.sql("SELECT count(*) FROM oid4vc_tenant_key WHERE public_jwk LIKE ? OR encode(private_key, 'escape') LIKE ?")
                .params("%" + d + "%", "%" + d + "%").query(Integer.class).single();
        assertThat(clear).isZero();

        // A second active key for the same purpose is refused by the database itself.
        assertThat(repository.insertActive(new TenantKey("env-bank", "issuer-signing", TenantKey.Status.ACTIVE,
                keys.rotate(bank, "issuer-signing").key(), first.certificate(), java.time.Instant.now(), null))).isFalse();
        assertThat(keys.publishedKeys(bank, "issuer-signing")).hasSize(2);

        // Another deployment's key-encryption key can't read them.
        var foreign = new JdbcTenantKeyRepository(jdbc, KeyEncryptor.ephemeral(), new TransactionTemplate(new DataSourceTransactionManager(dataSource)));
        assertThatThrownBy(() -> foreign.findActive("env-bank", "issuer-signing")).isInstanceOf(Exception.class);

        tenants.delete("env-bank");
        assertThat(repository.findAll("env-bank")).isEmpty();
    }
}
