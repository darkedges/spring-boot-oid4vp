package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;

import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.HashMap;

/**
 * A parsed {@code MobileSecurityObject} (ISO 18013-5 §9.1.2.4) — the structure {@code IssuerAuth} signs,
 * carrying per-namespace digests of the disclosed {@code IssuerSignedItem}s, the device's public key, and
 * the credential's validity window.
 */
record MobileSecurityObject(
        String docType,
        String digestAlgorithm,
        java.util.Map<String, java.util.Map<Long, byte[]>> valueDigests,
        ECPublicKey deviceKey,
        Instant validFrom,
        Instant validUntil) {

    static MobileSecurityObject parse(DataItem item) {
        Map mso = CborUtil.requireMap(item);

        String docType = CborUtil.requireText(CborUtil.get(mso, "docType"));
        String digestAlgorithm = CborUtil.requireText(CborUtil.get(mso, "digestAlgorithm"));
        java.util.Map<String, java.util.Map<Long, byte[]>> valueDigests = parseValueDigests(CborUtil.get(mso, "valueDigests"));

        Map deviceKeyInfo = CborUtil.requireMap(CborUtil.get(mso, "deviceKeyInfo"));
        ECPublicKey deviceKey = parseCoseKey(CborUtil.requireMap(CborUtil.get(deviceKeyInfo, "deviceKey")));

        Map validityInfo = CborUtil.requireMap(CborUtil.get(mso, "validityInfo"));
        Instant validFrom = parseTdate(CborUtil.get(validityInfo, "validFrom"));
        Instant validUntil = parseTdate(CborUtil.get(validityInfo, "validUntil"));

        return new MobileSecurityObject(docType, digestAlgorithm, valueDigests, deviceKey, validFrom, validUntil);
    }

    private static java.util.Map<String, java.util.Map<Long, byte[]>> parseValueDigests(DataItem item) {
        Map byNamespace = CborUtil.requireMap(item);
        java.util.Map<String, java.util.Map<Long, byte[]>> result = new HashMap<>();
        for (DataItem namespaceKey : byNamespace.getKeys()) {
            String namespace = CborUtil.requireText(namespaceKey);
            Map digestIds = CborUtil.requireMap(byNamespace.get(namespaceKey));
            java.util.Map<Long, byte[]> digests = new HashMap<>();
            for (DataItem digestIdKey : digestIds.getKeys()) {
                digests.put(CborUtil.requireLong(digestIdKey), CborUtil.requireBytes(digestIds.get(digestIdKey)));
            }
            result.put(namespace, digests);
        }
        return result;
    }

    private static ECPublicKey parseCoseKey(Map coseKey) {
        // COSE_Key EC2 labels (RFC 9053 §7.1.1): kty(1)=2 (EC2), crv(-1)=1 (P-256), x(-2), y(-3).
        byte[] x = CborUtil.requireBytes(coseKey.get(new NegativeInteger(-2)));
        byte[] y = CborUtil.requireBytes(coseKey.get(new NegativeInteger(-3)));
        try {
            ECKey ecKey = new ECKey.Builder(Curve.P_256, Base64URL.encode(x), Base64URL.encode(y)).build();
            return ecKey.toECPublicKey();
        } catch (JOSEException e) {
            throw new MdocVerificationException("deviceKeyInfo.deviceKey is not a valid P-256 public key", e);
        }
    }

    private static Instant parseTdate(DataItem item) {
        if (!item.hasTag() || item.getTag().getValue() != 0) {
            throw new MdocVerificationException("expected a tdate (tag 0 date-time string)");
        }
        try {
            return Instant.parse(CborUtil.requireText(item));
        } catch (Exception e) {
            throw new MdocVerificationException("invalid tdate value: " + item, e);
        }
    }
}
