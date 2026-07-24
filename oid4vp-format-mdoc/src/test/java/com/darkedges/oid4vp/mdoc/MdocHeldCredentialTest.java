package com.darkedges.oid4vp.mdoc;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.MsoMdocMeta;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MdocHeldCredentialTest {

    private static final String DOC_TYPE = "org.iso.18013.5.1.mDL";
    private static final String NAMESPACE = "org.iso.18013.5.1";

    @Test
    void parsesDocTypeClaimsViewAndDeviceKeyFromARealSignedIssuerSigned() throws Exception {
        KeyPair issuerKeys = TestMdocFixtures.generateEcKeyPair();
        KeyPair deviceKeys = TestMdocFixtures.generateEcKeyPair();
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        byte[] issuerSignedBytes = TestMdocFixtures.buildIssuerSigned(
                issuerKeys, (ECPublicKey) deviceKeys.getPublic(), now, DOC_TYPE, NAMESPACE,
                java.util.Map.of("given_name", "Jean", "family_name", "Dupont"));

        MdocHeldCredential credential = MdocHeldCredential.parse(issuerSignedBytes);

        assertThat(credential.format()).isEqualTo(CredentialFormat.MSO_MDOC);
        assertThat(credential.docType()).isEqualTo(DOC_TYPE);
        assertThat(credential.hasCryptographicHolderBinding()).isTrue();
        assertThat(credential.deviceKey()).isEqualTo(deviceKeys.getPublic());

        JsonNode claims = credential.claimsView().get(NAMESPACE);
        assertThat(claims.get("given_name").asText()).isEqualTo("Jean");
        assertThat(claims.get("family_name").asText()).isEqualTo("Dupont");
    }

    @Test
    void matchesMetaOnlyAgainstTheSameDocType() throws Exception {
        KeyPair issuerKeys = TestMdocFixtures.generateEcKeyPair();
        KeyPair deviceKeys = TestMdocFixtures.generateEcKeyPair();
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        byte[] issuerSignedBytes = TestMdocFixtures.buildIssuerSigned(
                issuerKeys, (ECPublicKey) deviceKeys.getPublic(), now, DOC_TYPE, NAMESPACE,
                java.util.Map.of("given_name", "Jean"));
        MdocHeldCredential credential = MdocHeldCredential.parse(issuerSignedBytes);

        assertThat(credential.matchesMeta(new MsoMdocMeta(DOC_TYPE))).isTrue();
        assertThat(credential.matchesMeta(new MsoMdocMeta("org.iso.18013.5.1.other"))).isFalse();
        // A meta object for a different format entirely must not match either.
        assertThat(credential.matchesMeta(new SdJwtVcMeta(List.of(DOC_TYPE)))).isFalse();
    }

    @Test
    void everyElementIsSelectivelyDisclosable() throws Exception {
        KeyPair issuerKeys = TestMdocFixtures.generateEcKeyPair();
        KeyPair deviceKeys = TestMdocFixtures.generateEcKeyPair();
        Instant now = Instant.parse("2026-01-01T00:00:00Z");

        byte[] issuerSignedBytes = TestMdocFixtures.buildIssuerSigned(
                issuerKeys, (ECPublicKey) deviceKeys.getPublic(), now, DOC_TYPE, NAMESPACE,
                java.util.Map.of("given_name", "Jean"));
        MdocHeldCredential credential = MdocHeldCredential.parse(issuerSignedBytes);

        assertThat(credential.isSelectivelyDisclosable(null)).isTrue();
    }
}
