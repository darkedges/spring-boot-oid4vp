package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;

/**
 * Real (not mocked) CBOR/COSE construction shared by this module's tests — there are no ISO 18013-5 test
 * vectors anywhere in this repo, so tests prove {@link MdocVerifier} and {@link MdocHeldCredential} by
 * building genuine signed structures from scratch: real EC keypairs, real COSE_Sign1 signatures, real
 * SHA-256 digests. A miniature stand-in for what Phase 4's real Wallet-side mdoc issuance will do.
 */
final class TestMdocFixtures {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TestMdocFixtures() {}

    /** Builds a signed {@code IssuerSigned} structure ({@code {nameSpaces, issuerAuth}}) as raw CBOR
     * bytes — thin wrapper over the real production {@link MdocIssuer}, single-namespace and no
     * x5chain, for tests that don't exercise issuer-key/cert-chain resolution. */
    static byte[] buildIssuerSigned(
            KeyPair issuerKeys, ECPublicKey deviceKey, Instant now, String docType, String namespace,
            java.util.Map<String, String> claims) {
        return MdocIssuer.issueIssuerSigned(
                issuerKeys.getPrivate(), java.util.List.of(), deviceKey, docType,
                java.util.Map.of(namespace, claims), now, now.plusSeconds(365L * 24 * 3600));
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

    static Map algHeader() {
        Map header = new Map();
        header.put(new UnsignedInteger(1), new NegativeInteger(-7)); // alg: ES256
        return header;
    }

    /** @param payloadForSigStructure the bytes to sign over (Sig_structure's payload slot)
     *  @param embeddedPayload the COSE_Sign1 array's own payload field -- the same bytes when embedded
     *                         ({@code IssuerAuth}), or {@code null} for detached signing ({@code DeviceAuth}). */
    static byte[] coseSign1(PrivateKey privateKey, byte[] protectedHeaderBytes, byte[] payloadForSigStructure, byte[] embeddedPayload)
            throws Exception {
        byte[] sigStructure = CborUtil.encode(new CborBuilder()
                .addArray()
                .add("Signature1")
                .add(protectedHeaderBytes)
                .add(new byte[0])
                .add(payloadForSigStructure)
                .end()
                .build()
                .get(0));

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(sigStructure);
        byte[] derSignature = signer.sign();
        byte[] concatSignature = ECDSA.transcodeSignatureToConcat(derSignature, ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256));

        var arrayBuilder = new CborBuilder().addArray().add(protectedHeaderBytes).add(new Map());
        arrayBuilder = embeddedPayload == null ? arrayBuilder.add(SimpleValue.NULL) : arrayBuilder.add(embeddedPayload);
        return CborUtil.encode(arrayBuilder.add(concatSignature).end().build().get(0));
    }

    static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    static JsonNode publicJwk(PublicKey publicKey) {
        try {
            ECKey jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey).build();
            return MAPPER.readTree(jwk.toJSONString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
