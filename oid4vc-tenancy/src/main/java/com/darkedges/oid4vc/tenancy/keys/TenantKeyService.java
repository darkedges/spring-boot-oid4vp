package com.darkedges.oid4vc.tenancy.keys;

import com.darkedges.oid4vc.tenancy.Tenant;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Each tenant's keys, by purpose. A key is generated here when first needed and its private part never leaves the service.
 *
 * <ul>
 *   <li>{@link #activeKey} signs: created on first use.</li>
 *   <li>{@link #publishedKeys} is what a JWKS shows: the active key and retired ones, so what they signed still verifies.</li>
 *   <li>{@link #rotate} retires the active key and makes a new one; {@link #removeRetired} stops publishing an old one.</li>
 * </ul>
 */
public final class TenantKeyService {

    private static final Pattern PURPOSE = Pattern.compile("^[a-z][a-z0-9-]{0,31}$");

    private final TenantKeyRepository keys;
    private final TenantCertificateAuthority authority;
    private final Set<String> purposes;

    public TenantKeyService(TenantKeyRepository keys, TenantCertificateAuthority authority, Set<String> purposes) {
        purposes.forEach(TenantKeyService::requireWellFormed);
        this.keys = keys;
        this.authority = authority;
        this.purposes = Set.copyOf(purposes);
    }

    public Set<String> purposes() {
        return purposes;
    }

    public TenantKey activeKey(Tenant tenant, String purpose) {
        requireKnown(purpose);
        return keys.findActive(tenant.id(), purpose).orElseGet(() -> {
            TenantKey created = generate(tenant, purpose);
            if (keys.insertActive(created)) return created;
            // Another instance created one at the same moment: use theirs.
            return keys.findActive(tenant.id(), purpose)
                    .orElseThrow(() -> new IllegalStateException("no active " + purpose + " key for tenant " + tenant.id()));
        });
    }

    public List<TenantKey> publishedKeys(Tenant tenant, String purpose) {
        requireKnown(purpose);
        return keys.findPublished(tenant.id(), purpose);
    }

    public List<TenantKey> allKeys(Tenant tenant) {
        return keys.findAll(tenant.id());
    }

    /** Retires the active key (it stays published) and returns its replacement. */
    public TenantKey rotate(Tenant tenant, String purpose) {
        TenantKey current = activeKey(tenant, purpose);
        TenantKey replacement = generate(tenant, purpose);
        keys.rotate(tenant.id(), purpose, current.kid(), replacement);
        return replacement;
    }

    public boolean removeRetired(Tenant tenant, String kid) {
        return keys.deleteRetired(tenant.id(), kid);
    }

    public TenantCertificateAuthority authority() {
        return authority;
    }

    private TenantKey generate(Tenant tenant, String purpose) {
        try {
            String kid = purpose + "-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
            ECKey pair = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).keyID(kid).generate();
            X509Certificate certificate = authority.issue(pair.toKeyPair(), tenant.id(), tenant.slug(), purpose);
            ECKey key = new ECKey.Builder(pair).x509CertChain(List.of(Base64.encode(certificate.getEncoded()))).build();
            return new TenantKey(tenant.id(), purpose, TenantKey.Status.ACTIVE, key, certificate, Instant.now(), null);
        } catch (JOSEException | CertificateEncodingException e) {
            throw new IllegalStateException("could not create a " + purpose + " key for tenant " + tenant.id(), e);
        }
    }

    private void requireKnown(String purpose) {
        if (!purposes.contains(purpose)) throw new IllegalArgumentException("unknown key purpose: " + purpose);
    }

    private static void requireWellFormed(String purpose) {
        if (purpose == null || !PURPOSE.matcher(purpose).matches()) throw new IllegalArgumentException("bad key purpose: " + purpose);
    }
}
