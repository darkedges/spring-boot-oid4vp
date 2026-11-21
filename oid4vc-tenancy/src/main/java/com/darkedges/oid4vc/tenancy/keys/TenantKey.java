package com.darkedges.oid4vc.tenancy.keys;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * One of a tenant's keys.
 *
 * @param purpose     what it signs, such as {@code issuer-signing}, {@code mdoc} or {@code request-object}
 * @param status      ACTIVE signs; RETIRED no longer signs but is still published, so what it signed still verifies
 * @param key         the EC P-256 key pair, its {@code kid} and {@code x5c} set
 * @param certificate its certificate, issued by the deployment's CA (or self-signed without one)
 */
public record TenantKey(String tenantId, String purpose, Status status, ECKey key, X509Certificate certificate,
                        Instant createdAt, Instant retiredAt) {

    public enum Status { ACTIVE, RETIRED }

    public TenantKey {
        Objects.requireNonNull(tenantId);
        Objects.requireNonNull(purpose);
        Objects.requireNonNull(status);
        Objects.requireNonNull(key);
        Objects.requireNonNull(certificate);
        if (!key.isPrivate()) throw new IllegalArgumentException("a tenant key holds its private part");
    }

    public String kid() {
        return key.getKeyID();
    }

    /** The public key to publish (JWKS), with its certificate chain. */
    public ECKey publicJwk() {
        return key.toPublicJWK();
    }

    /** The {@code x5c} chain: this key's certificate (the CA's is distributed separately, as a trust anchor). */
    public List<Base64> x5c() {
        return key.getX509CertChain();
    }

    public TenantKey retired(Instant at) {
        return new TenantKey(tenantId, purpose, Status.RETIRED, key, certificate, createdAt, at);
    }
}
