package com.darkedges.oid4vc.tenancy.keys;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

/**
 * Issues the certificate for each tenant key: what an SD-JWT VC's or mdoc's {@code x5c}/{@code x5chain} carries, and what a verifier's
 * {@code x509_hash} client identifier is computed from. Wallets and verifiers trust the deployment's CA, and through it every tenant.
 *
 * <p>Without a CA (development) each key gets a self-signed certificate, which nothing trusts unless pinned.
 */
public final class TenantCertificateAuthority {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final PrivateKey caKey;
    private final X509Certificate caCertificate;
    private final Duration validity;

    private TenantCertificateAuthority(PrivateKey caKey, X509Certificate caCertificate, Duration validity) {
        this.caKey = caKey;
        this.caCertificate = caCertificate;
        this.validity = validity;
    }

    public static TenantCertificateAuthority of(PrivateKey caKey, X509Certificate caCertificate, Duration validity) {
        return new TenantCertificateAuthority(caKey, caCertificate, validity);
    }

    /** Issues self-signed certificates (no CA configured). */
    public static TenantCertificateAuthority selfSigned(Duration validity) {
        return new TenantCertificateAuthority(null, null, validity);
    }

    /** Loads the CA's key and certificate from a PKCS#12 keystore entry. */
    public static TenantCertificateAuthority fromKeyStore(InputStream pkcs12, char[] password, String alias, Duration validity) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(pkcs12, password);
        String entry = alias != null && !alias.isBlank() ? alias : store.aliases().nextElement();
        if (!store.isKeyEntry(entry)) throw new IllegalArgumentException("the CA keystore entry \"" + entry + "\" holds no private key");
        return new TenantCertificateAuthority((PrivateKey) store.getKey(entry, password), (X509Certificate) store.getCertificate(entry), validity);
    }

    /** The CA certificate that verifiers and wallets trust; empty when certificates are self-signed. */
    public Optional<X509Certificate> caCertificate() {
        return Optional.ofNullable(caCertificate);
    }

    /**
     * Issues a certificate for a tenant's key: subject {@code CN=<slug> <purpose>, O=<tenant id>}, digital signature only.
     */
    public X509Certificate issue(KeyPair subjectKeys, String tenantId, String slug, String purpose) {
        try {
            Instant now = Instant.now();
            X500Name subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, slug + " " + purpose)
                    .addRDN(BCStyle.O, tenantId)
                    .build();
            X500Name issuer = caCertificate == null ? subject : X500Name.getInstance(caCertificate.getSubjectX500Principal().getEncoded());
            PrivateKey signingKey = caKey == null ? subjectKeys.getPrivate() : caKey;
            PublicKey issuerPublic = caCertificate == null ? subjectKeys.getPublic() : caCertificate.getPublicKey();

            JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, new BigInteger(127, RANDOM).add(BigInteger.ONE),
                    Date.from(now.minusSeconds(300)), Date.from(now.plus(validity)), subject, subjectKeys.getPublic())
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
                    .addExtension(Extension.subjectKeyIdentifier, false, extensions.createSubjectKeyIdentifier(subjectKeys.getPublic()))
                    .addExtension(Extension.authorityKeyIdentifier, false, extensions.createAuthorityKeyIdentifier(issuerPublic));
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(signingKey)).build(signingKey);
            return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        } catch (Exception e) {
            throw new IllegalStateException("could not issue a certificate for tenant " + tenantId + " (" + purpose + ")", e);
        }
    }

    private static String signatureAlgorithm(PrivateKey key) {
        return switch (key.getAlgorithm()) {
            case "EC", "ECDSA" -> "SHA256withECDSA";
            case "RSA" -> "SHA256withRSA";
            default -> throw new IllegalArgumentException("unsupported CA key algorithm: " + key.getAlgorithm());
        };
    }
}
