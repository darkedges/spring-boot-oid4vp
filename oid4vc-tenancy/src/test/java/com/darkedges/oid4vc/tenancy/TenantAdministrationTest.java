package com.darkedges.oid4vc.tenancy;

import com.darkedges.oid4vc.tenancy.admin.ConsoleAccount;
import com.darkedges.oid4vc.tenancy.admin.ConsoleAccount.Role;
import com.darkedges.oid4vc.tenancy.admin.TenantAdministration;
import com.darkedges.oid4vc.tenancy.admin.TenantSettingsValidator;
import com.darkedges.oid4vc.tenancy.keys.InMemoryTenantKeyRepository;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TenantAdministrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final InMemoryTenantRepository tenants = new InMemoryTenantRepository();
    private final TenantAdministration admin;

    private final ConsoleAccount bankAdmin = new ConsoleAccount("u1", "admin@bank.example", Role.ORG_ADMIN, "org-1", Map.of("env-bank", "Risk E Bank"));
    private final ConsoleAccount bankViewer = new ConsoleAccount("u2", "viewer@bank.example", Role.ORG_VIEWER, "org-1", Map.of("env-bank", "Risk E Bank"));
    private final ConsoleAccount shopAdmin = new ConsoleAccount("u3", "admin@shop.example", Role.ORG_ADMIN, "org-2", Map.of("env-shop", "Shop"));
    private final ConsoleAccount platform = new ConsoleAccount("u0", "ops@platform.example", Role.ADMIN, null, Map.of());

    TenantAdministrationTest() throws Exception {
        TenantKeyService keys = new TenantKeyService(new InMemoryTenantKeyRepository(), TenantKeysTest.testCa(), Set.of("issuer-signing"));
        TenantSettingsValidator validator = settings -> settings.has("bad") ? List.of("\"bad\" is not a setting") : List.of();
        admin = new TenantAdministration(tenants, keys, validator, List.of(URI.create("https://issuer.zkp.au")), "issuer");
    }

    private static JsonNode json(String text) throws Exception {
        return MAPPER.readTree(text);
    }

    @Test
    void anOrganizationAdministratorEnablesTheirEnvironmentWithASlugFromItsName() throws Exception {
        var created = admin.put(bankAdmin, "env-bank", json("{\"settings\":{\"display\":\"Bank\"}}"));
        assertThat(created.status()).isEqualTo(201);
        assertThat(created.body().path("slug").asText()).isEqualTo("risk-e-bank");
        assertThat(created.body().path("organizationId").asText()).isEqualTo("org-1");
        assertThat(created.body().path("urls").toString())
                .contains("https://risk-e-bank.issuer.zkp.au").contains("https://issuer.zkp.au/t/risk-e-bank");
        assertThat(created.body().path("certificateAuthority").path("pem").asText()).startsWith("-----BEGIN CERTIFICATE-----");
    }

    @Test
    void anotherOrganizationIsToldTheTenantDoesNotExist() throws Exception {
        admin.put(bankAdmin, "env-bank", json("{}"));
        assertThat(admin.get(shopAdmin, "env-bank").status()).isEqualTo(404);
        assertThat(admin.put(shopAdmin, "env-bank", json("{\"enabled\":false}")).status()).isEqualTo(404);
        assertThat(admin.rotate(shopAdmin, "env-bank", "issuer-signing").status()).isEqualTo(404);
        // Nor can they create a tenant for an environment that isn't theirs.
        assertThat(admin.put(shopAdmin, "env-elsewhere", json("{}")).status()).isEqualTo(404);
        assertThat(admin.list(shopAdmin).body().path("tenants")).isEmpty();
        assertThat(admin.list(bankAdmin).body().path("tenants")).hasSize(1);
    }

    @Test
    void aViewerMayLookButNotChange() throws Exception {
        admin.put(bankAdmin, "env-bank", json("{}"));
        assertThat(admin.get(bankViewer, "env-bank").status()).isEqualTo(200);
        assertThat(admin.put(bankViewer, "env-bank", json("{\"enabled\":false}")).status()).isEqualTo(403);
        assertThat(admin.rotate(bankViewer, "env-bank", "issuer-signing").status()).isEqualTo(403);
        assertThat(tenants.findById("env-bank").orElseThrow().enabled()).isTrue();
    }

    @Test
    void secretsAreWriteOnly() throws Exception {
        admin.put(bankAdmin, "env-bank", json("{\"settings\":{\"proofing\":{\"enabled\":true},\"secrets\":{\"proofingCallback\":\"s3cret\"}}}"));
        var shown = admin.get(bankAdmin, "env-bank").body();
        assertThat(shown.toString()).doesNotContain("s3cret");
        assertThat(shown.path("settings").path("secrets").path("proofingCallback").path("set").asBoolean()).isTrue();

        // Saving what was shown keeps the secret; null removes it.
        admin.put(bankAdmin, "env-bank", json("{\"settings\":" + shown.path("settings") + "}"));
        assertThat(TenantSecrets.secret(tenants.findById("env-bank").orElseThrow(), "proofingCallback")).isEqualTo("s3cret");
        admin.put(bankAdmin, "env-bank", json("{\"settings\":{\"secrets\":{\"proofingCallback\":null}}}"));
        assertThat(TenantSecrets.secret(tenants.findById("env-bank").orElseThrow(), "proofingCallback")).isNull();
    }

    @Test
    void badSettingsAndSlugsAreRefused() throws Exception {
        assertThat(admin.put(bankAdmin, "env-bank", json("{\"slug\":\"admin\"}")).status()).isEqualTo(400);
        assertThat(admin.put(bankAdmin, "env-bank", json("{\"slug\":\"Not A Label\"}")).status()).isEqualTo(400);
        var invalid = admin.put(bankAdmin, "env-bank", json("{\"settings\":{\"bad\":1}}"));
        assertThat(invalid.status()).isEqualTo(400);
        assertThat(invalid.body().path("problems").get(0).asText()).contains("bad");

        admin.put(shopAdmin, "env-shop", json("{\"slug\":\"shop\"}"));
        assertThat(admin.put(bankAdmin, "env-bank", json("{\"slug\":\"shop\"}")).status()).isEqualTo(409);
    }

    @Test
    void keysAreRotatedAndRetiredOnesRemoved() throws Exception {
        admin.put(bankAdmin, "env-bank", json("{}"));
        // The first rotation creates the first key and replaces it: one active, one retired.
        var rotated = admin.rotate(bankAdmin, "env-bank", "issuer-signing");
        assertThat(rotated.status()).isEqualTo(200);
        JsonNode keys = rotated.body().path("keys");
        assertThat(keys).hasSize(2);
        String retired = null, active = null;
        for (JsonNode k : keys) {
            if (k.path("status").asText().equals("RETIRED")) retired = k.path("kid").asText();
            else active = k.path("kid").asText();
        }
        assertThat(admin.removeRetiredKey(bankAdmin, "env-bank", active).status()).isEqualTo(409);
        assertThat(admin.removeRetiredKey(bankAdmin, "env-bank", retired).body().path("keys")).hasSize(1);
        assertThat(admin.rotate(bankAdmin, "env-bank", "nope").status()).isEqualTo(400);
    }

    @Test
    void thePlatformAdministratorManagesAnyTenant() throws Exception {
        admin.put(bankAdmin, "env-bank", json("{}"));
        assertThat(admin.put(platform, "env-bank", json("{\"enabled\":false}")).status()).isEqualTo(200);
        assertThat(admin.list(platform).body().path("tenants")).hasSize(1);
    }
}
