package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSA;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * A parsed COSE_Sign1 structure (RFC 9052 §4.2): {@code [protected: bstr, unprotected: map,
 * payload: bstr / nil, signature: bstr]}. mdoc uses this for both {@code IssuerAuth} (signing the MSO)
 * and {@code DeviceAuth}'s {@code deviceSignature} (signing {@code DeviceAuthentication}).
 *
 * <p>Signature verification hardcodes ES256/P-256, the only algorithm this project uses anywhere —
 * matching the established "hardcode Curve.P_256" pattern elsewhere. COSE's ES256 signature is the same
 * raw, concatenated {@code r || s} format JOSE uses, so converting it to the DER form
 * {@code java.security.Signature} expects reuses Nimbus's existing (already-a-dependency)
 * {@code ECDSA.transcodeSignatureToDER} rather than hand-rolling ASN.1 encoding.
 */
final class CoseSign1 {

    private static final UnsignedInteger LABEL_ALG = new UnsignedInteger(1);
    private static final UnsignedInteger LABEL_X5CHAIN = new UnsignedInteger(33);
    private static final NegativeInteger ALG_ES256 = new NegativeInteger(-7);

    private final byte[] protectedHeaderBytes;
    private final Map protectedHeader;
    private final Map unprotectedHeader;
    private final byte[] payload;
    private final byte[] signature;

    private CoseSign1(byte[] protectedHeaderBytes, Map protectedHeader, Map unprotectedHeader, byte[] payload, byte[] signature) {
        this.protectedHeaderBytes = protectedHeaderBytes;
        this.protectedHeader = protectedHeader;
        this.unprotectedHeader = unprotectedHeader;
        this.payload = payload;
        this.signature = signature;
    }

    static CoseSign1 parse(DataItem item) {
        Array array = CborUtil.requireArray(item);
        List<DataItem> elements = array.getDataItems();
        if (elements.size() != 4) {
            throw new MdocVerificationException("COSE_Sign1 must have exactly 4 elements, had " + elements.size());
        }

        byte[] protectedHeaderBytes = CborUtil.requireBytes(elements.get(0));
        Map protectedHeader = protectedHeaderBytes.length == 0
                ? new Map()
                : CborUtil.requireMap(CborUtil.decodeSingle(protectedHeaderBytes));
        Map unprotectedHeader = CborUtil.requireMap(elements.get(1));

        DataItem payloadItem = elements.get(2);
        byte[] payload = payloadItem instanceof SimpleValue sv && sv.getSimpleValueType() == co.nstant.in.cbor.model.SimpleValueType.NULL
                ? null
                : CborUtil.requireBytes(payloadItem);

        byte[] signature = CborUtil.requireBytes(elements.get(3));

        return new CoseSign1(protectedHeaderBytes, protectedHeader, unprotectedHeader, payload, signature);
    }

    /**
     * Builds a signed COSE_Sign1 array from scratch (ES256/P-256): {@code [protected, unprotected,
     * payload-or-nil, signature]}. The counterpart to {@link #parse}/{@link #verify} — used by
     * {@code MdocIssuer} (issuer-signed {@code IssuerAuth}) and {@code MdocPresentationBuilder}
     * (device-signed {@code DeviceAuth}).
     *
     * @param x5chain        signing certificate chain (RFC 9360) to embed in the unprotected header —
     *                       only {@code IssuerAuth} carries one; pass {@code List.of()} for
     *                       {@code DeviceAuth}, which signs with a bare device key.
     * @param embeddedPayload the bytes to carry in the array's own payload slot, or {@code null} for
     *                        detached signing (the payload field becomes {@code nil} — {@code DeviceAuth}).
     * @param signedPayload   the bytes actually signed over (the {@code Sig_structure}'s payload slot) —
     *                        the same as {@code embeddedPayload} unless detached, in which case the
     *                        caller supplies it externally (e.g. {@code DeviceAuthentication} bytes).
     */
    static DataItem sign1(PrivateKey privateKey, List<String> x5chain, byte[] embeddedPayload, byte[] signedPayload) {
        Map protectedHeader = new Map();
        protectedHeader.put(LABEL_ALG, ALG_ES256);
        byte[] protectedHeaderBytes = CborUtil.encode(protectedHeader);

        Map unprotectedHeader = new Map();
        if (!x5chain.isEmpty()) {
            if (x5chain.size() == 1) {
                unprotectedHeader.put(LABEL_X5CHAIN, new ByteString(Base64.getDecoder().decode(x5chain.get(0))));
            } else {
                Array chainArray = new Array();
                x5chain.forEach(cert -> chainArray.add(new ByteString(Base64.getDecoder().decode(cert))));
                unprotectedHeader.put(LABEL_X5CHAIN, chainArray);
            }
        }

        byte[] sigStructure = CborUtil.encode(new CborBuilder()
                .addArray()
                .add("Signature1")
                .add(protectedHeaderBytes)
                .add(new byte[0])
                .add(signedPayload)
                .end()
                .build()
                .get(0));

        byte[] derSignature;
        try {
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(privateKey);
            signer.update(sigStructure);
            derSignature = signer.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("failed to sign COSE_Sign1", e);
        }

        byte[] concatSignature;
        try {
            concatSignature = ECDSA.transcodeSignatureToConcat(derSignature, ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256));
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to encode COSE_Sign1 signature", e);
        }

        var arrayBuilder = new CborBuilder().addArray().add(protectedHeaderBytes).add(unprotectedHeader);
        arrayBuilder = embeddedPayload == null ? arrayBuilder.add(SimpleValue.NULL) : arrayBuilder.add(embeddedPayload);
        return arrayBuilder.add(concatSignature).end().build().get(0);
    }

    byte[] payload() {
        if (payload == null) {
            throw new MdocVerificationException("COSE_Sign1 has a detached (nil) payload, which this module does not support");
        }
        return payload;
    }


    /** The signing certificate chain from the {@code x5chain} header (RFC 9360) — checked in the
     * protected header first, then unprotected — leaf-first, base64 (standard, not URL-safe) DER, the
     * same shape {@link com.darkedges.oid4vp.core.response.IssuerKeyResolver}'s {@code certificateChain}
     * parameter expects. */
    List<String> x5chain() {
        DataItem value = protectedHeader.get(LABEL_X5CHAIN);
        if (value == null) {
            value = unprotectedHeader.get(LABEL_X5CHAIN);
        }
        if (value == null) {
            return List.of();
        }
        List<String> certs = new ArrayList<>();
        if (value instanceof ByteString) {
            certs.add(Base64.getEncoder().encodeToString(CborUtil.requireBytes(value)));
        } else {
            for (DataItem entry : CborUtil.requireArray(value).getDataItems()) {
                certs.add(Base64.getEncoder().encodeToString(CborUtil.requireBytes(entry)));
            }
        }
        return certs;
    }

    /** Verifies the signature over this COSE_Sign1's embedded payload — {@code IssuerAuth}'s usage,
     * where the payload (the MSO) is carried inline.
     * @param context a short label (e.g. {@code "IssuerAuth"}) included in any failure message, so a
     *                caller verifying more than one COSE_Sign1 (mdoc always does: IssuerAuth and
     *                DeviceAuth) can tell which one actually failed. */
    void verify(PublicKey publicKey, String context) {
        verifyOverPayload(publicKey, payload(), context);
    }

    /** Verifies the signature with a payload supplied externally rather than embedded — mdoc's
     * {@code DeviceAuth.deviceSignature} usage, whose COSE_Sign1 payload field is {@code nil} because the
     * signed content ({@code DeviceAuthentication}) is reconstructed by both sides rather than
     * transmitted.
     * @param context see {@link #verify(PublicKey, String)}. */
    void verifyDetached(PublicKey publicKey, byte[] detachedPayload, String context) {
        verifyOverPayload(publicKey, detachedPayload, context);
    }

    private void verifyOverPayload(PublicKey publicKey, byte[] payloadBytes, String context) {
        DataItem algItem = protectedHeader.get(LABEL_ALG);
        if (algItem != null && !algItem.equals(ALG_ES256)) {
            throw new MdocVerificationException(
                    context + ": unsupported COSE algorithm (only ES256 is supported): " + algItem);
        }

        byte[] sigStructure = CborUtil.encode(new CborBuilder()
                .addArray()
                .add("Signature1")
                .add(protectedHeaderBytes)
                .add(new byte[0])
                .add(payloadBytes)
                .end()
                .build()
                .get(0));

        byte[] derSignature;
        try {
            derSignature = ECDSA.transcodeSignatureToDER(signature);
        } catch (JOSEException e) {
            throw new MdocVerificationException(context + ": COSE_Sign1 signature is not a valid ES256 signature", e);
        }

        try {
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(sigStructure);
            if (!verifier.verify(derSignature)) {
                throw new MdocVerificationException(context + ": COSE_Sign1 signature verification failed");
            }
        } catch (GeneralSecurityException e) {
            throw new MdocVerificationException(context + ": COSE_Sign1 signature verification failed", e);
        }
    }
}
