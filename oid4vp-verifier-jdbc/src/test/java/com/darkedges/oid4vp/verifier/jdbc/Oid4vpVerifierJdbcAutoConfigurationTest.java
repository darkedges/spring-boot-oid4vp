package com.darkedges.oid4vp.verifier.jdbc;

import com.darkedges.oid4vp.spring.boot.autoconfigure.Oid4vpVerifierAutoConfiguration;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpEphemeralEncryptionKeyRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpTransactionResultRepository;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class Oid4vpVerifierJdbcAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(Oid4vpVerifierJdbcAutoConfiguration.class, Oid4vpVerifierAutoConfiguration.class))
            .withBean(DataSource.class, () -> new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:1/none"));

    @Test
    void offUnlessAskedFor() {
        runner.run(context -> {
            assertThat(context).hasNotFailed().doesNotHaveBean(VerifierEntryTable.class);
            assertThat(context.getBean(Oid4vpAuthorizationRequestRepository.class)).isNotInstanceOf(JdbcVerifierStores.AuthorizationRequests.class);
        });
    }

    @Test
    void refusesToKeepVerifiedIdentitiesWithoutAnEncryptionKey() {
        runner.withPropertyValues("oid4vp.verifier.store.type=jdbc", "oid4vp.verifier.store.initialize-schema=false")
                .run(context -> assertThat(context).hasFailed().getFailure().hasStackTraceContaining("encryption-key is required"));
    }

    @Test
    void theVerifiersInMemoryStoresBackOff() {
        runner.withPropertyValues("oid4vp.verifier.store.type=jdbc", "oid4vp.verifier.store.initialize-schema=false",
                        "oid4vp.verifier.store.encryption-key=" + Base64.getEncoder().encodeToString(new byte[32]))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(Oid4vpAuthorizationRequestRepository.class)).isInstanceOf(JdbcVerifierStores.AuthorizationRequests.class);
                    assertThat(context.getBean(Oid4vpEphemeralEncryptionKeyRepository.class)).isInstanceOf(JdbcVerifierStores.EphemeralEncryptionKeys.class);
                    assertThat(context.getBean(Oid4vpTransactionResultRepository.class)).isInstanceOf(JdbcVerifierStores.TransactionResults.class);
                });
    }
}
