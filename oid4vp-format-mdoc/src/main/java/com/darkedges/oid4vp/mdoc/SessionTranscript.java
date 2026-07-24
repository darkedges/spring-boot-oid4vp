package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.Array;
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
        return CborUtil.encode(buildDataItem(clientId, nonce, jwkThumbprint, responseUri));
    }

    /** Same as {@link #build}, but returns the {@link DataItem} directly rather than its encoded bytes --
     * for callers (both {@code MdocVerifier} and {@code MdocPresentationBuilder}) that only need it to
     * immediately embed as a nested element of a larger CBOR structure being built, sparing them an
     * encode-then-immediately-decode-back-to-a-DataItem round trip through {@link CborUtil#decodeSingle}. */
    static DataItem buildDataItem(String clientId, String nonce, Optional<byte[]> jwkThumbprint, String responseUri) {
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

        Array sessionTranscript = new Array();
        sessionTranscript.add(SimpleValue.NULL);
        sessionTranscript.add(SimpleValue.NULL);
        Array openId4VpHandover = new Array();
        openId4VpHandover.add(new co.nstant.in.cbor.model.UnicodeString("OpenID4VPHandover"));
        openId4VpHandover.add(new ByteString(sha256(handoverInfo)));
        sessionTranscript.add(openId4VpHandover);
        return sessionTranscript;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // SHA-256 is guaranteed available (JDK 21)
        }
    }
}
