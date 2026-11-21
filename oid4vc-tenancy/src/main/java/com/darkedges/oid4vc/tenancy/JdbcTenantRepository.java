package com.darkedges.oid4vc.tenancy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;

/** Tenants in PostgreSQL, table {@code oid4vc_tenant} (see {@code oid4vc-tenancy/schema-postgresql.sql}). */
public final class JdbcTenantRepository implements TenantRepository {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String COLUMNS = "id, organization_id, slug, enabled, settings::text AS settings, created_at, updated_at";

    private final JdbcClient jdbc;

    public JdbcTenantRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<Tenant> findById(String id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM oid4vc_tenant WHERE id = ?").param(id).query(JdbcTenantRepository::map).optional();
    }

    @Override
    public Optional<Tenant> findBySlug(String slug) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM oid4vc_tenant WHERE slug = ?").param(slug).query(JdbcTenantRepository::map).optional();
    }

    @Override
    public List<Tenant> findAll() {
        return jdbc.sql("SELECT " + COLUMNS + " FROM oid4vc_tenant ORDER BY slug").query(JdbcTenantRepository::map).list();
    }

    @Override
    public Tenant save(Tenant tenant) {
        try {
            jdbc.sql("""
                    INSERT INTO oid4vc_tenant (id, organization_id, slug, enabled, settings, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?::jsonb, ?, ?)
                    ON CONFLICT (id) DO UPDATE SET organization_id = EXCLUDED.organization_id, slug = EXCLUDED.slug,
                        enabled = EXCLUDED.enabled, settings = EXCLUDED.settings, updated_at = EXCLUDED.updated_at
                    """)
                    .params(tenant.id(), tenant.organizationId(), tenant.slug(), tenant.enabled(), json(tenant.settings()),
                            Timestamp.from(tenant.createdAt()), Timestamp.from(tenant.updatedAt()))
                    .update();
        } catch (DuplicateKeyException e) {
            throw new SlugTakenException(tenant.slug());
        }
        return tenant;
    }

    @Override
    public boolean delete(String id) {
        return jdbc.sql("DELETE FROM oid4vc_tenant WHERE id = ?").param(id).update() > 0;
    }

    private static String json(ObjectNode node) {
        try {
            return MAPPER.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Tenant map(ResultSet rs, int row) throws SQLException {
        ObjectNode settings;
        try {
            settings = (ObjectNode) MAPPER.readTree(rs.getString("settings"));
        } catch (JsonProcessingException | ClassCastException e) {
            throw new SQLException("unreadable settings for tenant " + rs.getString("id"), e);
        }
        return new Tenant(rs.getString("id"), rs.getString("organization_id"), rs.getString("slug"), rs.getBoolean("enabled"),
                settings, rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("updated_at").toInstant());
    }
}
