package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.eval.ClaimSelection;
import com.darkedges.oid4vp.core.dcql.eval.CredentialPresentationPlan;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.mdoc.MdocHeldCredential;
import com.darkedges.oid4vp.mdoc.MdocIssuer;
import com.darkedges.oid4vp.sdjwt.SdJwtVcHeldCredential;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** {@link MdocPresentationBuilderAdapter} — had no test at all before; only exercised transitively via
 * {@code WalletAuthorizationResponseBuilder} in manual/demo round trips. */
class MdocPresentationBuilderAdapterTest {

    private static MdocHeldCredential issueMdocCredential() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair issuerKeys = generator.generateKeyPair();
        KeyPair deviceKeys = generator.generateKeyPair();
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        byte[] issuerSigned = MdocIssuer.issueIssuerSigned(
                issuerKeys.getPrivate(), List.of(), (ECPublicKey) deviceKeys.getPublic(), "org.iso.18013.5.1.mDL",
                Map.of("org.iso.18013.5.1", Map.of("given_name", "Jean")), now, now.plusSeconds(3600));
        return MdocHeldCredential.parse(issuerSigned);
    }

    private static PresentationBuildParams params(HolderKeyResolver holderKeyResolver) {
        return new PresentationBuildParams(
                "nonce", "x509_hash:test-client", "x509_hash:test-client", "https://verifier.example.org/response",
                Optional.empty(), holderKeyResolver, Clock.systemUTC());
    }

    @Test
    void rejectsAHeldCredentialThatIsNotAnMdoc() {
        SdJwtVcHeldCredential wrongType =
                SdJwtVcHeldCredential.parse(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_issuance.txt"));
        CredentialPresentationPlan plan = new CredentialPresentationPlan(wrongType, ClaimSelection.MandatoryOnly.INSTANCE);
        HolderKeyResolver holderKeyResolver = credential -> Optional.empty();

        assertThatThrownBy(() -> new MdocPresentationBuilderAdapter().build(plan, params(holderKeyResolver)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("MdocHeldCredential");
    }

    @Test
    void throwsWhenNoDevicePrivateKeyIsAvailable() throws Exception {
        MdocHeldCredential credential = issueMdocCredential();
        CredentialPresentationPlan plan = new CredentialPresentationPlan(credential, ClaimSelection.MandatoryOnly.INSTANCE);
        // resolvePrivateKey() defaults to Optional.empty() unless overridden.
        HolderKeyResolver holderKeyResolver = c -> Optional.empty();

        assertThatThrownBy(() -> new MdocPresentationBuilderAdapter().build(plan, params(holderKeyResolver)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no device private key");
    }

    @Test
    void buildsAPresentationWhenAPrivateKeyIsAvailable() throws Exception {
        MdocHeldCredential credential = issueMdocCredential();
        CredentialPresentationPlan plan = new CredentialPresentationPlan(credential, ClaimSelection.MandatoryOnly.INSTANCE);
        HolderKeyResolver holderKeyResolver = new HolderKeyResolver() {
            @Override
            public Optional<com.nimbusds.jose.JWSSigner> resolveSigner(com.darkedges.oid4vp.core.dcql.eval.HeldCredential c) {
                return Optional.empty();
            }

            @Override
            public Optional<java.security.PrivateKey> resolvePrivateKey(com.darkedges.oid4vp.core.dcql.eval.HeldCredential c) {
                // Any EC private key exercises the signing path; correctness of the resulting signature
                // is covered by MdocPresentationBuilderTest in oid4vp-format-mdoc.
                try {
                    java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
                    generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
                    return Optional.of(generator.generateKeyPair().getPrivate());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        PresentationEntry entry = new MdocPresentationBuilderAdapter().build(plan, params(holderKeyResolver));

        assertThat(entry).isInstanceOf(PresentationEntry.StringPresentation.class);
        assertThat(((PresentationEntry.StringPresentation) entry).value()).isNotBlank();
    }
}
