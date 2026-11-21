package com.darkedges.oid4vp.demo.verifier;

import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * {@link MultiTenantDemoVerifierTest} on the "tenancy" and "postgres" profiles: tenants, their keys and the verifier's state in
 * PostgreSQL. Set {@code OID4VP_TEST_POSTGRES_URL} (a JDBC URL with user and password) to run it.
 */
@EnabledIfEnvironmentVariable(named = "OID4VP_TEST_POSTGRES_URL", matches = ".+")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"tenancy", "postgres"})
class MultiTenantDemoVerifierPostgresTest extends MultiTenantDemoVerifierTest {

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        // A clean database: anything left by an earlier run was encrypted under that run's (random) keys.
        try (var connection = java.sql.DriverManager.getConnection(System.getenv("OID4VP_TEST_POSTGRES_URL"));
             var statement = connection.createStatement()) {
            statement.execute("DROP TABLE IF EXISTS oid4vc_tenant_key, oid4vc_tenant, oid4vp_verifier_entry");
        } catch (java.sql.SQLException e) {
            throw new IllegalStateException(e);
        }
        registry.add("spring.datasource.url", () -> System.getenv("OID4VP_TEST_POSTGRES_URL"));
        registry.add("spring.datasource.username", () -> "");
        registry.add("spring.datasource.password", () -> "");
        registry.add("oid4vc.tenancy.keys.encryption-key", MultiTenantDemoVerifierPostgresTest::randomKey);
        registry.add("oid4vp.verifier.store.encryption-key", MultiTenantDemoVerifierPostgresTest::randomKey);
    }
}
