package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.ClaimsQuery;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.dcql.MsoMdocMeta;
import com.darkedges.oid4vp.core.dcql.eval.CredentialStore;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.core.response.VpToken;
import com.darkedges.oid4vp.core.response.VpTokenReader;
import com.darkedges.oid4vp.core.response.VpTokenWriter;
import com.darkedges.oid4vp.mdoc.MdocHeldCredential;
import com.darkedges.oid4vp.mdoc.MdocIssuer;
import com.darkedges.oid4vp.mdoc.MdocVerifier;
import com.darkedges.oid4vp.verifier.AuthorizationResponseValidator;
import com.darkedges.oid4vp.verifier.encryption.ResponseDecryptor;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Full round trip for {@code mso_mdoc}, mirroring {@link WalletAuthorizationResponseBuilderTest}'s
 * {@code dc+sd-jwt} coverage but through the entire real pipeline a live deployment actually uses: builds
 * a Wallet response, encrypts it with the real {@link ResponseEncryptor} to the Verifier's real
 * response-encryption key, decrypts it with the real {@link ResponseDecryptor}, and validates it with the
 * real {@link AuthorizationResponseValidator}/{@link MdocVerifier}.
 *
 * <p>This is deliberately the one mdoc test in this project that never existed before a real OpenID
 * Foundation conformance run found two live bugs in this exact path (a wrong {@code SessionTranscript}
 * shape, and a missing tag-24 wrap on {@code DeviceAuthenticationBytes}) — every other mdoc test proves
 * correctness against itself (build with one function, verify with its matching counterpart), which
 * cannot catch a mistake shared by both sides. Exercising response encryption end-to-end here (rather than
 * {@code Optional.empty()} for the response-encryption key, as the unencrypted-path tests do) is what
 * actually exercises the {@code OpenID4VPHandover} {@code jwkThumbprint} construction on both sides.
 */
class WalletAuthorizationResponseBuilderMdocTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String DOC_TYPE = "org.iso.18013.5.1.mDL";
    private static final String NAMESPACE = "org.iso.18013.5.1";
    private static final String CLIENT_ID = "x509_hash:test-client";
    private static final String RESPONSE_URI = "https://verifier.example.org/response";
    private static final String NONCE = "wallet-core-mdoc-nonce-1";

    private record IssuedCredential(MdocHeldCredential credential, KeyPair issuerKeys, KeyPair deviceKeys) {}

    private static IssuedCredential issueCredential() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair issuerKeys = generator.generateKeyPair();
        KeyPair deviceKeys = generator.generateKeyPair();
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        byte[] issuerSigned = MdocIssuer.issueIssuerSigned(
                issuerKeys.getPrivate(), List.of(), (ECPublicKey) deviceKeys.getPublic(), DOC_TYPE,
                Map.of(NAMESPACE, Map.of("given_name", "Jean", "family_name", "Dupont")),
                now, now.plusSeconds(3600));

        return new IssuedCredential(MdocHeldCredential.parse(issuerSigned), issuerKeys, deviceKeys);
    }

    private static DcqlQuery requestGivenNameAndFamilyName() {
        ClaimsQuery givenName = ClaimsQuery.of("a", ClaimsPathPointer.of(NAMESPACE, "given_name"));
        ClaimsQuery familyName = ClaimsQuery.of("b", ClaimsPathPointer.of(NAMESPACE, "family_name"));
        CredentialQuery credentialQuery = CredentialQuery.builder("mdl", CredentialFormat.MSO_MDOC)
                .meta(new MsoMdocMeta(DOC_TYPE))
                .claims(List.of(givenName, familyName))
                .build();
        return DcqlQuery.of(List.of(credentialQuery));
    }

    private static ObjectNode asJwkSet(JsonNode jwk) {
        ArrayNode keys = JsonNodeFactory.instance.arrayNode().add(jwk);
        return JsonNodeFactory.instance.objectNode().set("keys", keys);
    }

    @Test
    void buildsEncryptsDecryptsAndVerifiesAnMdocPresentationEndToEnd() throws Exception {
        IssuedCredential issued = issueCredential();
        CredentialStore store = CredentialStore.of(List.of((HeldCredential) issued.credential()));

        ECKey verifierEncryptionKey = new ECKeyGenerator(Curve.P_256).keyID("verifier-enc-1").generate();
        JsonNode verifierPublicJwk = MAPPER.readTree(verifierEncryptionKey.toPublicJWK().toJSONString());
        JsonNode verifierPrivateJwks = asJwkSet(MAPPER.readTree(verifierEncryptionKey.toJSONString()));

        HolderKeyResolver holderKeyResolver = new HolderKeyResolver() {
            @Override
            public Optional<com.nimbusds.jose.JWSSigner> resolveSigner(HeldCredential credential) {
                return Optional.empty(); // mdoc never goes through the JWSSigner path
            }

            @Override
            public Optional<PrivateKey> resolvePrivateKey(HeldCredential credential) {
                return Optional.of(issued.deviceKeys().getPrivate());
            }
        };

        WalletAuthorizationResponseBuilder walletBuilder =
                new WalletAuthorizationResponseBuilder(Map.of(CredentialFormat.MSO_MDOC, new MdocPresentationBuilderAdapter()));

        PresentationBuildParams buildParams = new PresentationBuildParams(
                NONCE, CLIENT_ID, CLIENT_ID, RESPONSE_URI, Optional.of(verifierPublicJwk), holderKeyResolver, Clock.systemUTC());

        WalletAuthorizationResponseResult result = walletBuilder.build(requestGivenNameAndFamilyName(), store, buildParams);

        assertThat(result).isInstanceOf(WalletAuthorizationResponseResult.Built.class);
        VpToken vpToken = ((WalletAuthorizationResponseResult.Built) result).vpToken();
        assertThat(vpToken.presentations()).containsOnlyKeys("mdl");

        // Encrypt the way a real Wallet posting to direct_post.jwt would.
        ObjectNode responsePayload = MAPPER.createObjectNode();
        responsePayload.set("vp_token", VpTokenWriter.write(vpToken));
        responsePayload.put("state", "the-state-value");
        String jwe = ResponseEncryptor.encrypt(responsePayload, asJwkSet(verifierPublicJwk), List.of("A128GCM"));

        // Decrypt + resolve the response-encryption key the way the real Verifier-side converter does.
        JsonNode decrypted = ResponseDecryptor.decrypt(jwe, verifierPrivateJwks);
        Optional<JsonNode> responseEncryptionPublicJwk = ResponseDecryptor.resolveResponseEncryptionPublicJwk(jwe, verifierPrivateJwks);
        assertThat(responseEncryptionPublicJwk).isPresent();
        VpToken decryptedVpToken = VpTokenReader.read(decrypted.get("vp_token"));

        // mdoc's IssuerAuth carries no x5chain in this fixture (issued with an empty cert chain), so the
        // Verifier must resolve the issuer key some other way -- reuse the real issuer public key directly,
        // exactly as a Verifier configured to trust this specific demo issuer out-of-band would.
        JsonNode issuerJwk = MAPPER.readTree(new com.nimbusds.jose.jwk.ECKey.Builder(
                        com.nimbusds.jose.jwk.Curve.P_256, (ECPublicKey) issued.issuerKeys().getPublic())
                .build().toJSONString());
        IssuerKeyResolver issuerKeyResolver = (issuer, keyId, certificateChain) -> Optional.of(issuerJwk);

        AuthorizationResponseValidator validator =
                new AuthorizationResponseValidator(Map.of(CredentialFormat.MSO_MDOC, new MdocVerifier()));

        Instant verifyTime = Instant.parse("2026-01-01T00:30:00Z");
        Map<String, List<VerifiedPresentation>> verified = validator.validate(
                requestGivenNameAndFamilyName(), decryptedVpToken, NONCE, CLIENT_ID, CLIENT_ID, RESPONSE_URI,
                responseEncryptionPublicJwk, issuerKeyResolver, Clock.fixed(verifyTime, ZoneOffset.UTC));

        JsonNode claims = verified.get("mdl").get(0).verifiedClaims().get(NAMESPACE);
        assertThat(claims.get("given_name").asText()).isEqualTo("Jean");
        assertThat(claims.get("family_name").asText()).isEqualTo("Dupont");
    }
}
