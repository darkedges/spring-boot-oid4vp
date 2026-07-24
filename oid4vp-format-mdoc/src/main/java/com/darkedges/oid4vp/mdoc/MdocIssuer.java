package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;

/**
 * Issues an mdoc credential: builds and signs an {@code IssuerSigned} structure ({@code nameSpaces} +
 * {@code issuerAuth}) — the CBOR bytes a Wallet stores and {@link MdocHeldCredential#parse(byte[])}
 * consumes. This is the issuer-side counterpart to {@link MdocVerifier}: this project doesn't implement
 * OpenID4VCI, so a demo Wallet calls this directly to self-issue its own credential (mirroring
 * {@code DemoCredentialConfig}'s SD-JWT VC self-issuance) rather than fetching one from a real issuance
 * endpoint.
 */
public final class MdocIssuer {

    private static final SecureRandom RANDOM = new SecureRandom();

    private MdocIssuer() {}

    /**
     * @param claimsByNamespace   the credential's disclosable data, grouped by namespace.
     * @param issuerCertificateChain the issuer's own signing certificate chain (RFC 9360 {@code x5chain}),
     *                                leaf-first, base64 (standard, not URL-safe) DER — embedded in
     *                                {@code IssuerAuth}'s unprotected header so a Verifier can resolve
     *                                the issuer's key the same way it does for SD-JWT VC's {@code x5c}.
     */
    public static byte[] issueIssuerSigned(
            PrivateKey issuerPrivateKey,
            List<String> issuerCertificateChain,
            ECPublicKey deviceKey,
            String docType,
            java.util.Map<String, java.util.Map<String, String>> claimsByNamespace,
            Instant validFrom,
            Instant validUntil) {
        Map nameSpaces = new Map();
        Map valueDigests = new Map();

        for (var namespaceEntry : claimsByNamespace.entrySet()) {
            Array itemsArray = new Array();
            Map digestsForNamespace = new Map();
            long digestId = 0;
            for (var claimEntry : namespaceEntry.getValue().entrySet()) {
                DataItem wrapped = wrapTag24(issuerSignedItem(digestId, claimEntry.getKey(), claimEntry.getValue()));
                itemsArray.add(wrapped);
                digestsForNamespace.put(new UnsignedInteger(digestId), new ByteString(sha256(CborUtil.encode(wrapped))));
                digestId++;
            }
            nameSpaces.put(new UnicodeString(namespaceEntry.getKey()), itemsArray);
            valueDigests.put(new UnicodeString(namespaceEntry.getKey()), digestsForNamespace);
        }

        Map mso = new Map();
        mso.put(new UnicodeString("version"), new UnicodeString("1.0"));
        mso.put(new UnicodeString("digestAlgorithm"), new UnicodeString("SHA-256"));
        mso.put(new UnicodeString("valueDigests"), valueDigests);
        Map deviceKeyInfo = new Map();
        deviceKeyInfo.put(new UnicodeString("deviceKey"), coseKey(deviceKey));
        mso.put(new UnicodeString("deviceKeyInfo"), deviceKeyInfo);
        mso.put(new UnicodeString("docType"), new UnicodeString(docType));
        Map validityInfo = new Map();
        validityInfo.put(new UnicodeString("signed"), tdate(validFrom));
        validityInfo.put(new UnicodeString("validFrom"), tdate(validFrom));
        validityInfo.put(new UnicodeString("validUntil"), tdate(validUntil));
        mso.put(new UnicodeString("validityInfo"), validityInfo);

        byte[] msoPayload = CborUtil.encode(wrapTag24(mso));
        DataItem issuerAuth = CoseSign1.sign1(issuerPrivateKey, issuerCertificateChain, msoPayload, msoPayload);

        Map issuerSigned = new Map();
        issuerSigned.put(new UnicodeString("nameSpaces"), nameSpaces);
        issuerSigned.put(new UnicodeString("issuerAuth"), issuerAuth);
        return CborUtil.encode(issuerSigned);
    }

    static DataItem wrapTag24(DataItem item) {
        ByteString wrapped = new ByteString(CborUtil.encode(item));
        wrapped.setTag(24);
        return wrapped;
    }

    static DataItem tdate(Instant instant) {
        UnicodeString text = new UnicodeString(instant.toString());
        text.setTag(0);
        return text;
    }

    static Map coseKey(ECPublicKey publicKey) {
        byte[] x = toFixedLength(publicKey.getW().getAffineX(), 32);
        byte[] y = toFixedLength(publicKey.getW().getAffineY(), 32);
        Map coseKey = new Map();
        coseKey.put(new UnsignedInteger(1), new UnsignedInteger(2)); // kty: EC2
        coseKey.put(new co.nstant.in.cbor.model.NegativeInteger(-1), new UnsignedInteger(1)); // crv: P-256
        coseKey.put(new co.nstant.in.cbor.model.NegativeInteger(-2), new ByteString(x));
        coseKey.put(new co.nstant.in.cbor.model.NegativeInteger(-3), new ByteString(y));
        return coseKey;
    }

    private static DataItem issuerSignedItem(long digestId, String elementIdentifier, String elementValue) {
        byte[] random = new byte[16];
        RANDOM.nextBytes(random);
        Map item = new Map();
        item.put(new UnicodeString("digestID"), new UnsignedInteger(digestId));
        item.put(new UnicodeString("random"), new ByteString(random));
        item.put(new UnicodeString("elementIdentifier"), new UnicodeString(elementIdentifier));
        item.put(new UnicodeString("elementValue"), new UnicodeString(elementValue));
        return item;
    }

    private static byte[] toFixedLength(java.math.BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        }
        byte[] fixed = new byte[length];
        if (raw.length > length) {
            System.arraycopy(raw, raw.length - length, fixed, 0, length);
        } else {
            System.arraycopy(raw, 0, fixed, length - raw.length, raw.length);
        }
        return fixed;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
