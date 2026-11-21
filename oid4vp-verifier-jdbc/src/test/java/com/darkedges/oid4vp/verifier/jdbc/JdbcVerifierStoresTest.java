package com.darkedges.oid4vp.verifier.jdbc;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.core.authority.AuthorityUtils;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The verifier's stores against a real PostgreSQL: set {@code OID4VP_TEST_POSTGRES_URL}, for example
 * {@code jdbc:postgresql://localhost:55435/verifier?user=verifier&password=verifier}. Skipped otherwise.
 */
@EnabledIfEnvironmentVariable(named = "OID4VP_TEST_POSTGRES_URL", matches = ".+")
class JdbcVerifierStoresTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private JdbcClient jdbc;
    private byte[] key;
    private VerifierEntryTable table;

    @BeforeEach
    void setUp() {
        var dataSource = new DriverManagerDataSource(System.getenv("OID4VP_TEST_POSTGRES_URL"));
        jdbc = JdbcClient.create(dataSource);
        jdbc.sql("DROP TABLE IF EXISTS oid4vp_verifier_entry").update();
        var schema = new ResourceDatabasePopulator(new ClassPathResource("oid4vp-verifier-jdbc/schema-postgresql.sql"));
        schema.execute(dataSource);
        schema.execute(dataSource); // idempotent
        key = new byte[32];
        new SecureRandom().nextBytes(key);
        table = new VerifierEntryTable(jdbc, key);
    }

    private static Oid4vpAuthorizationRequestContext context(String registrationKey, String state, Instant expires) {
        DcqlQuery dcql = DcqlQuery.of(List.of(CredentialQuery.builder("employee", CredentialFormat.DC_SD_JWT)
                .meta(new SdJwtVcMeta(List.of("https://vct.example/employee"))).build()));
        return new Oid4vpAuthorizationRequestContext(registrationKey, state, "nonce-" + state, new ClientIdentifierPrefix.X509Hash("h"),
                dcql, URI.create("https://verifier.test/login/oid4vp/direct-post/login"), expires, Optional.of("tx-" + state), Optional.of("verifier-" + state));
    }

    @Test
    void aRequestRoundTripsAndIsConsumedOnlyByItsRegistrationOnce() {
        var requests = new JdbcVerifierStores.AuthorizationRequests(table, Clock.systemUTC());
        Oid4vpAuthorizationRequestContext saved = context("bank/login", "s1", Instant.now().plusSeconds(60));
        requests.save(saved);

        String dump = jdbc.sql("SELECT kind || key || owner || encode(payload, 'escape') FROM oid4vp_verifier_entry").query(String.class).single();
        assertThat(dump).doesNotContain("s1").doesNotContain("bank/login").doesNotContain("nonce-s1");

        assertThat(requests.consume("s1", "shop/login")).as("another tenant's registration").isEmpty();
        Oid4vpAuthorizationRequestContext back = requests.consume("s1", "bank/login").orElseThrow();
        assertThat(back).usingRecursiveComparison().ignoringFields("dcqlQuery").isEqualTo(saved);
        assertThat(back.dcqlQuery().credentials()).hasSize(1);
        assertThat(requests.consume("s1", "bank/login")).isEmpty();

        requests.save(context("bank/login", "s2", Instant.now().minusSeconds(1)));
        assertThat(requests.consume("s2", "bank/login")).as("expired").isEmpty();
    }

    @Test
    void aRequestIsConsumedOnceEvenWhenInstancesRace() throws Exception {
        new JdbcVerifierStores.AuthorizationRequests(table, Clock.systemUTC()).save(context("login", "race", Instant.now().plusSeconds(60)));
        var pool = Executors.newFixedThreadPool(8);
        List<Future<Boolean>> attempts = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            attempts.add(pool.submit(() -> new JdbcVerifierStores.AuthorizationRequests(new VerifierEntryTable(jdbc, key), Clock.systemUTC())
                    .consume("race", "login").isPresent()));
        }
        int winners = 0;
        for (Future<Boolean> attempt : attempts) if (attempt.get()) winners++;
        pool.shutdown();
        assertThat(winners).isEqualTo(1);
    }

    @Test
    void ephemeralKeysAreListedForTheirRegistrationOnlyWhileLive() throws Exception {
        var keys = new JdbcVerifierStores.EphemeralEncryptionKeys(table);
        Instant now = Instant.now();
        keys.save("bank/login", MAPPER.readTree("{\"kty\":\"EC\",\"kid\":\"k1\",\"d\":\"secret\"}"), now.plusSeconds(60));
        keys.save("bank/login", MAPPER.readTree("{\"kty\":\"EC\",\"kid\":\"k2\",\"d\":\"secret\"}"), now.minusSeconds(1));
        keys.save("shop/login", MAPPER.readTree("{\"kty\":\"EC\",\"kid\":\"k1\",\"d\":\"secret\"}"), now.plusSeconds(60));

        var bank = keys.resolveLiveKeys("bank/login", now).path("keys");
        assertThat(bank).hasSize(1);
        assertThat(bank.get(0).path("kid").asText()).isEqualTo("k1");
        assertThat(keys.resolveLiveKeys("shop/login", now).path("keys")).hasSize(1);
        assertThat(keys.resolveLiveKeys("other/login", now).path("keys")).isEmpty();
    }

    @Test
    void aSameDeviceResultIsCollectedOnceWithItsCodeAndAWrongCodeLeavesIt() {
        var results = new JdbcVerifierStores.TransactionResults(table, Clock.systemUTC(), Duration.ofMinutes(5));
        Oid4vpAuthenticationToken token = new Oid4vpAuthenticationToken(new Oid4vpPrincipal(Map.of("employee", List.of(
                new VerifiedPresentation("employee", CredentialFormat.DC_SD_JWT, MAPPER.createObjectNode().put("given_name", "Jane"), Optional.empty())))),
                AuthorityUtils.NO_AUTHORITIES, "tx-1");
        token.setRegistrationKey("bank/login");
        results.save("bank/tx-1", "code-1", token);

        assertThat(jdbc.sql("SELECT encode(payload, 'escape') FROM oid4vp_verifier_entry").query(String.class).single()).doesNotContain("Jane");
        assertThat(results.consume("bank/tx-1", "wrong")).isEmpty();
        var back = (Oid4vpAuthenticationToken) results.consume("bank/tx-1", "code-1").orElseThrow();
        assertThat(back.tenantId()).isEqualTo("bank");
        assertThat(back.transactionId()).contains("tx-1");
        assertThat(back.getPrincipal().claim("employee", "given_name").orElseThrow().asText()).isEqualTo("Jane");
        assertThat(back.isAuthenticated()).isTrue();
        assertThat(results.consume("bank/tx-1", "code-1")).isEmpty();
    }

    @Test
    void anotherKeyCannotReadTheEntries() {
        new JdbcVerifierStores.AuthorizationRequests(table, Clock.systemUTC()).save(context("login", "s3", Instant.now().plusSeconds(60)));
        byte[] other = new byte[32];
        new SecureRandom().nextBytes(other);
        org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                new JdbcVerifierStores.AuthorizationRequests(new VerifierEntryTable(jdbc, other), Clock.systemUTC()).consume("s3", "login"))
                .isInstanceOf(IllegalStateException.class);
    }
}
