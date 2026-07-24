package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.SimpleValue;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/**
 * Builds the CBOR-encoded {@code SessionTranscript} mdoc's {@code DeviceAuth} is computed over, per
 * OpenID4VP 1.1 §"Handover and SessionTranscript Definitions" > "Invocation via Redirects" (the
 * {@code OpenID4VPHandover} variant; the Digital Credentials API has a separate, unimplemented
 * {@code OpenID4VPDCAPIHandover} using {@code origin} instead of {@code clientId}/{@code responseUri}):
 * <pre>
 * SessionTranscript = [ null, null, OpenID4VPHandover ]
 * OpenID4VPHandover = [ "OpenID4VPHandover", sha256(CBOR(OpenID4VPHandoverInfo)) ]
 * OpenID4VPHandoverInfo = [ clientId, nonce, jwkThumbprint, responseUri ]
 * </pre>
 * {@code jwkThumbprint} is the RFC 7638 SHA-256 thumbprint of the Verifier's response-encryption public
 * key (the same key {@code client_metadata.jwks} carries) when the response is encrypted, else CBOR
 * {@code null} — both sides derive it independently from a key they already have, unlike an earlier draft
 * of this handover that required the Wallet to invent and communicate a nonce back to the Verifier.
 */
final class SessionTranscript {

    private SessionTranscript() {}

    static byte[] build(String clientId, String nonce, Optional<byte[]> jwkThumbprint, String responseUri) {
        DataItem thumbprintItem = jwkThumbprint.<DataItem>map(ByteString::new).orElse(SimpleValue.NULL);
        byte[] handoverInfo = CborUtil.encode(new CborBuilder()
                .addArray()
                .add(clientId)
                .add(nonce)
                .add(thumbprintItem)
                .add(responseUri)
                .end()
                .build()
                .get(0));

        return CborUtil.encode(new CborBuilder()
                .addArray()
                .add(SimpleValue.NULL)
                .add(SimpleValue.NULL)
                .addArray()
                .add("OpenID4VPHandover")
                .add(sha256(handoverInfo))
                .end()
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
