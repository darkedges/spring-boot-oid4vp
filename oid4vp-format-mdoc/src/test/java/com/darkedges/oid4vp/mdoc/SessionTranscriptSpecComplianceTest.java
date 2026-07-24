package com.darkedges.oid4vp.mdoc;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link SessionTranscript#build} encoded against the exact non-normative worked example from OpenID4VP
 * 1.1 §"Handover and SessionTranscript Definitions" (docs/1.1/openid-4-verifiable-presentations-1_1.md,
 * "Invocation via Redirects"), asserted byte-for-byte against the spec's own published hex.
 *
 * <p>This exists because the original implementation was built against an outdated draft's
 * {@code [clientIdHash, responseUriHash, nonce]}/{@code mdocGeneratedNonce} handover shape rather than the
 * published {@code OpenID4VPHandover} — a real bug caught only by a live OpenID Foundation conformance run,
 * not by any test, since the self-issued test fixtures build and verify with the same (then-wrong)
 * function on both sides. Locking the encoding against the spec's own independently-published bytes here
 * means any future regression of this shape is caught immediately, without needing a live conformance run.
 */
class SessionTranscriptSpecComplianceTest {

    private static final String CLIENT_ID = "x509_san_dns:example.com";
    private static final String NONCE = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
    private static final byte[] JWK_THUMBPRINT =
            HexFormat.of().parseHex("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047");
    private static final String RESPONSE_URI = "https://example.com/response";

    @Test
    void matchesTheSpecsPublishedSessionTranscriptExampleExactly() {
        byte[] sessionTranscript = SessionTranscript.build(CLIENT_ID, NONCE, Optional.of(JWK_THUMBPRINT), RESPONSE_URI);

        String expected = "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e"
                + "ed494cefdd9d95240d254b046b11b68013722aad38ac";
        assertThat(HexFormat.of().formatHex(sessionTranscript)).isEqualTo(expected);
    }

    @Test
    void jwkThumbprintIsCborNullWhenTheResponseIsUnencrypted() {
        // Per spec: "Otherwise, the third element MUST be null" -- not omitted, not an empty byte string.
        byte[] sessionTranscript = SessionTranscript.build(CLIENT_ID, NONCE, Optional.empty(), RESPONSE_URI);

        // [null, null, ["OpenID4VPHandover", hash-of-info-with-null-thumbprint]] -- still 3 top-level
        // elements with the two leading CBOR nulls (0xf6) untouched by whether the thumbprint is present.
        String hex = HexFormat.of().formatHex(sessionTranscript);
        assertThat(hex).startsWith("83f6f6"); // array(3), null, null
    }
}
