package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.MsoMdocMeta;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.PresentationVerificationParams;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * There are no real ISO 18013-5 test vectors anywhere in this repo, so this test hand-builds a genuine
 * signed {@code DeviceResponse} (via {@link TestMdocFixtures}) the same way {@code SdJwtVerifierEndToEndTest}'s
 * fixtures prove SD-JWT verification: real EC keypairs, real COSE_Sign1 signatures, real digests — not
 * mocked structures — then runs it through the actual production {@link MdocVerifier}.
 */
class MdocVerifierTest {

    private static final String DOC_TYPE = "org.iso.18013.5.1.mDL";
    private static final String NAMESPACE = "org.iso.18013.5.1";
    private static final String CLIENT_ID = "x509_hash:test-client";
    private static final String RESPONSE_URI = "https://verifier.example.org/response";
    private static final String NONCE = "test-nonce";

    @Test
    void verifiesAWellFormedDeviceResponse() throws Exception {
        KeyPair issuerKeys = TestMdocFixtures.generateEcKeyPair();
        KeyPair deviceKeys = TestMdocFixtures.generateEcKeyPair();
        JsonNode encryptionJwk = TestMdocFixtures.publicJwk(TestMdocFixtures.generateEcKeyPair().getPublic());
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        String presentation = buildDeviceResponse(
                issuerKeys, deviceKeys, encryptionJwk, now, java.util.Map.of("given_name", "Jean", "family_name", "Dupont"));

        VerifiedPresentation result = new MdocVerifier().verify(
                new PresentationEntry.StringPresentation(presentation), params(issuerKeys, encryptionJwk, now));

        assertThat(result.format()).isEqualTo(CredentialFormat.MSO_MDOC);
        assertThat(result.holderKeyConfirmed()).isPresent();
        JsonNode claims = result.verifiedClaims().get(NAMESPACE);
        assertThat(claims.get("given_name").asText()).isEqualTo("Jean");
        assertThat(claims.get("family_name").asText()).isEqualTo("Dupont");
    }

    @Test
    void rejectsATamperedElementValue() throws Exception {
        KeyPair issuerKeys = TestMdocFixtures.generateEcKeyPair();
        KeyPair deviceKeys = TestMdocFixtures.generateEcKeyPair();
        JsonNode encryptionJwk = TestMdocFixtures.publicJwk(TestMdocFixtures.generateEcKeyPair().getPublic());
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        // Build normally, then splice in a different elementValue for "given_name" without touching its
        // digest -- exactly what a tampered disclosure looks like. Same byte length as the original ("Jean"
        // -> "Anne") so the CBOR length-prefix stays valid and this genuinely exercises the digest check,
        // rather than just failing to parse at all.
        String presentation = buildDeviceResponse(
                issuerKeys, deviceKeys, encryptionJwk, now, java.util.Map.of("given_name", "Jean", "family_name", "Dupont"));
        byte[] deviceResponseBytes = Base64.getUrlDecoder().decode(presentation);
        String raw = new String(deviceResponseBytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        assertThat(raw).contains("Jean");
        String tampered = raw.replace("Jean", "Anne");
        String tamperedPresentation = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tampered.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));

        assertThatThrownBy(() -> new MdocVerifier().verify(
                new PresentationEntry.StringPresentation(tamperedPresentation), params(issuerKeys, encryptionJwk, now)))
                .isInstanceOf(MdocVerificationException.class)
                .hasMessageContaining("digest mismatch");
    }

    @Test
    void rejectsWhenTheSessionTranscriptDoesNotMatch() throws Exception {
        KeyPair issuerKeys = TestMdocFixtures.generateEcKeyPair();
        KeyPair deviceKeys = TestMdocFixtures.generateEcKeyPair();
        JsonNode encryptionJwk = TestMdocFixtures.publicJwk(TestMdocFixtures.generateEcKeyPair().getPublic());
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        String presentation = buildDeviceResponse(
                issuerKeys, deviceKeys, encryptionJwk, now, java.util.Map.of("given_name", "Jean", "family_name", "Dupont"));

        CredentialQuery query = CredentialQuery.builder("mdl", CredentialFormat.MSO_MDOC)
                .meta(new MsoMdocMeta(DOC_TYPE))
                .build();
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) ->
                Optional.of(TestMdocFixtures.publicJwk(issuerKeys.getPublic()));
        // A different nonce means the Verifier reconstructs a different SessionTranscript than the one the
        // "Wallet" actually signed DeviceAuthentication over -- DeviceAuth verification must fail.
        PresentationVerificationParams wrongNonceParams = new PresentationVerificationParams(
                query, "a-different-nonce", CLIENT_ID, CLIENT_ID, RESPONSE_URI, Optional.of(encryptionJwk),
                issuerKeyResolver, Clock.fixed(now, ZoneOffset.UTC));

        assertThatThrownBy(() -> new MdocVerifier().verify(new PresentationEntry.StringPresentation(presentation), wrongNonceParams))
                .isInstanceOf(MdocVerificationException.class)
                .hasMessageContaining("COSE_Sign1 signature verification failed");
    }

    private static PresentationVerificationParams params(KeyPair issuerKeys, JsonNode encryptionJwk, Instant now) {
        CredentialQuery query = CredentialQuery.builder("mdl", CredentialFormat.MSO_MDOC)
                .meta(new MsoMdocMeta(DOC_TYPE))
                .build();
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) ->
                Optional.of(TestMdocFixtures.publicJwk(issuerKeys.getPublic()));
        return new PresentationVerificationParams(
                query, NONCE, CLIENT_ID, CLIENT_ID, RESPONSE_URI, Optional.of(encryptionJwk),
                issuerKeyResolver, Clock.fixed(now, ZoneOffset.UTC));
    }

    private static String buildDeviceResponse(
            KeyPair issuerKeys, KeyPair deviceKeys, JsonNode encryptionJwk, Instant now, java.util.Map<String, String> claims)
            throws Exception {
        byte[] issuerSignedBytes = TestMdocFixtures.buildIssuerSigned(
                issuerKeys, (ECPublicKey) deviceKeys.getPublic(), now, DOC_TYPE, NAMESPACE, claims);
        DataItem issuerSigned = CborUtil.decodeSingle(issuerSignedBytes);

        DataItem deviceNameSpacesBytes = TestMdocFixtures.wrapTag24(new Map());
        byte[] jwkThumbprint = com.nimbusds.jose.jwk.JWK.parse(encryptionJwk.toString()).computeThumbprint().decode();
        byte[] sessionTranscript = SessionTranscript.build(CLIENT_ID, NONCE, Optional.of(jwkThumbprint), RESPONSE_URI);
        byte[] deviceAuthentication = CborUtil.encode(new CborBuilder()
                .addArray()
                .add("DeviceAuthentication")
                .add(CborUtil.decodeSingle(sessionTranscript))
                .add(DOC_TYPE)
                .add(deviceNameSpacesBytes)
                .end()
                .build()
                .get(0));
        byte[] deviceAuthenticationBytes = CborUtil.encode(TestMdocFixtures.wrapTag24(CborUtil.decodeSingle(deviceAuthentication)));
        byte[] deviceSignatureCose = TestMdocFixtures.coseSign1(
                deviceKeys.getPrivate(), CborUtil.encode(TestMdocFixtures.algHeader()), deviceAuthenticationBytes, null);

        Map deviceAuth = new Map();
        deviceAuth.put(new UnicodeString("deviceSignature"), CborUtil.decodeSingle(deviceSignatureCose));
        Map deviceSigned = new Map();
        deviceSigned.put(new UnicodeString("nameSpaces"), deviceNameSpacesBytes);
        deviceSigned.put(new UnicodeString("deviceAuth"), deviceAuth);

        Map document = new Map();
        document.put(new UnicodeString("docType"), new UnicodeString(DOC_TYPE));
        document.put(new UnicodeString("issuerSigned"), issuerSigned);
        document.put(new UnicodeString("deviceSigned"), deviceSigned);

        Array documents = new Array();
        documents.add(document);
        Map deviceResponse = new Map();
        deviceResponse.put(new UnicodeString("version"), new UnicodeString("1.0"));
        deviceResponse.put(new UnicodeString("documents"), documents);
        deviceResponse.put(new UnicodeString("status"), new UnsignedInteger(0));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(CborUtil.encode(deviceResponse));
    }
}
