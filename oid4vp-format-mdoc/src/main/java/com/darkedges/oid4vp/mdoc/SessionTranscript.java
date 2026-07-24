package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.SimpleValue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Builds the CBOR-encoded {@code SessionTranscript} mdoc's {@code DeviceAuth} is computed over, per
 * OpenID4VP's {@code OID4VPHandover} (ISO 18013-7 Annex B): binds the presentation to this specific
 * Authorization Request rather than mdoc's native proximity/QR-code flow (hence the two leading
 * {@code null}s, where a proximity {@code DeviceEngagementBytes}/{@code EReaderKeyBytes} pair would go).
 * <pre>
 * SessionTranscript = [ null, null, OID4VPHandover ]
 * OID4VPHandover     = [ clientIdHash, responseUriHash, nonce ]
 * clientIdHash        = SHA-256(CBOR([client_id, mdocGeneratedNonce]))
 * responseUriHash     = SHA-256(CBOR([response_uri, mdocGeneratedNonce]))
 * </pre>
 * {@code mdocGeneratedNonce} is Wallet-generated and carried back to the Verifier via the encrypted
 * response's JWE {@code apu} header (see {@code ResponseDecryptor.extractMdocGeneratedNonce}) — it has no
 * other channel, since the Verifier needs it before it can even attempt this reconstruction.
 */
final class SessionTranscript {

    private SessionTranscript() {}

    static byte[] build(String clientId, String responseUri, String nonce, String mdocGeneratedNonce) {
        byte[] clientIdHash = sha256(encodePair(clientId, mdocGeneratedNonce));
        byte[] responseUriHash = sha256(encodePair(responseUri, mdocGeneratedNonce));

        return CborUtil.encode(new CborBuilder()
                .addArray()
                .add(SimpleValue.NULL)
                .add(SimpleValue.NULL)
                .addArray()
                .add(clientIdHash)
                .add(responseUriHash)
                .add(nonce)
                .end()
                .end()
                .build()
                .get(0));
    }

    private static byte[] encodePair(String value, String mdocGeneratedNonce) {
        return CborUtil.encode(new CborBuilder()
                .addArray()
                .add(value)
                .add(mdocGeneratedNonce)
                .end()
                .build()
                .get(0));
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // SHA-256 is guaranteed available (JDK 21)
        }
    }
}
