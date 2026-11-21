package com.darkedges.oid4vc.tenancy;

import com.darkedges.oid4vc.tenancy.keys.InMemoryTenantKeyRepository;
import com.darkedges.oid4vc.tenancy.keys.KeyEncryptor;
import com.darkedges.oid4vc.tenancy.keys.TenantCertificateAuthority;
import com.darkedges.oid4vc.tenancy.keys.TenantKey;
import com.darkedges.oid4vc.tenancy.keys.TenantKeyService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TenantKeysTest {

    static TenantCertificateAuthority testCa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair caKeys = generator.generateKeyPair();
        // A self-signed CA certificate: issue one to itself, then use it as the authority.
        var caCert = TenantCertificateAuthority.selfSigned(Duration.ofDays(3650)).issue(caKeys, "platform", "test-ca", "ca");
        return TenantCertificateAuthority.of(caKeys.getPrivate(), caCert, Duration.ofDays(365));
    }

    private final Tenant bank = Tenant.create("env-bank", "org-1", "bank");
    private final Tenant shop = Tenant.create("env-shop", "org-2", "shop");

    @Test
    void privateKeysAreEncryptedBoundToTheirTenantAndKid() {
        KeyEncryptor encryptor = KeyEncryptor.ephemeral();
        byte[] secret = "{\"d\":\"private\"}".getBytes(StandardCharsets.UTF_8);
        byte[] stored = encryptor.encrypt(secret, "env-bank", "kid-1");
        assertThat(new String(stored, StandardCharsets.ISO_8859_1)).doesNotContain("private");
        assertThat(encryptor.decrypt(stored, "env-bank", "kid-1")).isEqualTo(secret);

        // Copied onto another tenant's row, or another key id: refused.
        assertThatThrownBy(() -> encryptor.decrypt(stored, "env-shop", "kid-1")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> encryptor.decrypt(stored, "env-bank", "kid-2")).isInstanceOf(IllegalStateException.class);
        // Another deployment's key-encryption key: refused.
        assertThatThrownBy(() -> KeyEncryptor.ephemeral().decrypt(stored, "env-bank", "kid-1")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new KeyEncryptor(new byte[16])).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void eachTenantGetsItsOwnActiveKeyCreatedOnceWithACaIssuedCertificate() throws Exception {
        TenantCertificateAuthority ca = testCa();
        TenantKeyService keys = new TenantKeyService(new InMemoryTenantKeyRepository(), ca, Set.of("issuer-signing", "mdoc"));

        TenantKey bankKey = keys.activeKey(bank, "issuer-signing");
        assertThat(keys.activeKey(bank, "issuer-signing").kid()).isEqualTo(bankKey.kid());
        TenantKey shopKey = keys.activeKey(shop, "issuer-signing");
        assertThat(shopKey.kid()).isNotEqualTo(bankKey.kid());
        assertThat(shopKey.publicJwk().toECPublicKey()).isNotEqualTo(bankKey.publicJwk().toECPublicKey());

        // The certificate is issued by the CA, names the tenant, and is for this key.
        bankKey.certificate().verify(ca.caCertificate().orElseThrow().getPublicKey());
        assertThat(bankKey.certificate().getSubjectX500Principal().getName()).contains("bank issuer-signing").contains("env-bank");
        assertThat(bankKey.certificate().getPublicKey()).isEqualTo(bankKey.publicJwk().toECPublicKey());
        assertThat(bankKey.x5c()).hasSize(1);
        assertThat(bankKey.publicJwk().isPrivate()).isFalse();

        // What one tenant signs, another tenant's key doesn't verify.
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), new JWTClaimsSet.Builder().issuer("https://bank.issuer.zkp.au").build());
        jwt.sign(new ECDSASigner(bankKey.key()));
        assertThat(jwt.verify(new ECDSAVerifier(bankKey.publicJwk()))).isTrue();
        assertThat(jwt.verify(new ECDSAVerifier(shopKey.publicJwk()))).isFalse();

        assertThatThrownBy(() -> keys.activeKey(bank, "unknown")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rotationKeepsTheOldKeyPublishedUntilItIsRemoved() throws Exception {
        TenantKeyService keys = new TenantKeyService(new InMemoryTenantKeyRepository(), testCa(), Set.of("issuer-signing"));
        TenantKey first = keys.activeKey(bank, "issuer-signing");
        TenantKey second = keys.rotate(bank, "issuer-signing");

        assertThat(keys.activeKey(bank, "issuer-signing").kid()).isEqualTo(second.kid());
        assertThat(keys.publishedKeys(bank, "issuer-signing")).extracting(TenantKey::kid).containsExactlyInAnyOrder(first.kid(), second.kid());
        assertThat(keys.publishedKeys(bank, "issuer-signing")).filteredOn(k -> k.kid().equals(first.kid()))
                .extracting(TenantKey::status).containsExactly(TenantKey.Status.RETIRED);

        assertThat(keys.removeRetired(bank, second.kid())).as("the active key can't be removed").isFalse();
        assertThat(keys.removeRetired(bank, first.kid())).isTrue();
        assertThat(keys.publishedKeys(bank, "issuer-signing")).extracting(TenantKey::kid).containsExactly(second.kid());
    }

    @Test
    void withoutACaCertificatesAreSelfSigned() throws Exception {
        TenantKeyService keys = new TenantKeyService(new InMemoryTenantKeyRepository(), TenantCertificateAuthority.selfSigned(Duration.ofDays(30)),
                Set.of("request-object"));
        TenantKey key = keys.activeKey(bank, "request-object");
        key.certificate().verify(key.certificate().getPublicKey());
        assertThat(keys.authority().caCertificate()).isEmpty();
    }
}
