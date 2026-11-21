package com.darkedges.oid4vc.tenancy.keys;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionOperations;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

/**
 * Keys in PostgreSQL, table {@code oid4vc_tenant_key}. The private key is stored only encrypted ({@link KeyEncryptor}); the public
 * JWK and certificate in the clear.
 */
public final class JdbcTenantKeyRepository implements TenantKeyRepository {

    private static final String COLUMNS = "tenant_id, kid, purpose, status, private_key, certificate, created_at, retired_at";

    private final JdbcClient jdbc;
    private final KeyEncryptor encryptor;
    private final TransactionOperations transactions;

    public JdbcTenantKeyRepository(JdbcClient jdbc, KeyEncryptor encryptor, TransactionOperations transactions) {
        this.jdbc = jdbc;
        this.encryptor = encryptor;
        this.transactions = transactions;
    }

    @Override
    public Optional<TenantKey> findActive(String tenantId, String purpose) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM oid4vc_tenant_key WHERE tenant_id = ? AND purpose = ? AND status = 'ACTIVE'")
                .params(tenantId, purpose).query(this::map).optional();
    }

    @Override
    public List<TenantKey> findPublished(String tenantId, String purpose) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM oid4vc_tenant_key WHERE tenant_id = ? AND purpose = ? ORDER BY created_at DESC")
                .params(tenantId, purpose).query(this::map).list();
    }

    @Override
    public List<TenantKey> findAll(String tenantId) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM oid4vc_tenant_key WHERE tenant_id = ? ORDER BY created_at DESC")
                .param(tenantId).query(this::map).list();
    }

    @Override
    public boolean insertActive(TenantKey key) {
        try {
            insert(key);
            return true;
        } catch (DuplicateKeyException e) {
            return false;
        }
    }

    @Override
    public void rotate(String tenantId, String purpose, String kid, TenantKey replacement) {
        transactions.executeWithoutResult(status -> {
            int retired = jdbc.sql("""
                    UPDATE oid4vc_tenant_key SET status = 'RETIRED', retired_at = now()
                    WHERE tenant_id = ? AND purpose = ? AND kid = ? AND status = 'ACTIVE'
                    """).params(tenantId, purpose, kid).update();
            if (retired != 1) throw new IllegalStateException("the active key changed meanwhile");
            insert(replacement);
        });
    }

    @Override
    public boolean deleteRetired(String tenantId, String kid) {
        return jdbc.sql("DELETE FROM oid4vc_tenant_key WHERE tenant_id = ? AND kid = ? AND status = 'RETIRED'")
                .params(tenantId, kid).update() > 0;
    }

    private void insert(TenantKey key) {
        byte[] encrypted = encryptor.encrypt(key.key().toJSONString().getBytes(StandardCharsets.UTF_8), key.tenantId(), key.kid());
        byte[] der;
        try {
            der = key.certificate().getEncoded();
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
        jdbc.sql("""
                INSERT INTO oid4vc_tenant_key (tenant_id, kid, purpose, status, public_jwk, private_key, certificate, created_at, retired_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)
                .params(key.tenantId(), key.kid(), key.purpose(), key.status().name(), key.publicJwk().toJSONString(), encrypted, der,
                        Timestamp.from(key.createdAt()), key.retiredAt() == null ? null : Timestamp.from(key.retiredAt()))
                .update();
    }

    private TenantKey map(ResultSet rs, int row) throws SQLException {
        String tenantId = rs.getString("tenant_id");
        String kid = rs.getString("kid");
        try {
            ECKey stored = ECKey.parse(new String(encryptor.decrypt(rs.getBytes("private_key"), tenantId, kid), StandardCharsets.UTF_8));
            byte[] der = rs.getBytes("certificate");
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            ECKey key = new ECKey.Builder(stored).keyID(kid).x509CertChain(List.of(Base64.encode(der))).build();
            Timestamp retired = rs.getTimestamp("retired_at");
            return new TenantKey(tenantId, rs.getString("purpose"), TenantKey.Status.valueOf(rs.getString("status")), key, certificate,
                    rs.getTimestamp("created_at").toInstant(), retired == null ? null : retired.toInstant());
        } catch (java.text.ParseException | CertificateException e) {
            throw new SQLException("unreadable key " + kid + " of tenant " + tenantId, e);
        }
    }
}
