package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Parses the issuance-form and presentation-form SD-JWT strings from
 * {@code docs/1.1/examples/sd_jwt_vcld/01/}, cross-checked against the sibling fixtures that were used
 * to generate them.
 */
class SdJwtParserTest {

    @Test
    void parsesIssuanceFormWithAllDisclosuresAndNoKeyBinding() {
        String issuance = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_issuance.txt");

        SdJwt parsed = SdJwtParser.parse(issuance);

        assertThat(parsed.disclosures()).hasSize(3);
        assertThat(parsed.keyBindingJwt()).isEmpty();
        assertThat(parsed.issuerSignedJwt().serialize())
                .isEqualTo(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_jws_part.txt"));
    }

    @Test
    void parsesPresentationFormWithOneDisclosureAndKeyBinding() {
        String presentation = FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_presentation.txt");

        SdJwt parsed = SdJwtParser.parse(presentation);

        assertThat(parsed.disclosures()).hasSize(1);
        assertThat(parsed.disclosures().get(0).claimName()).contains("givenName");
        assertThat(parsed.keyBindingJwt()).isPresent();
        assertThat(parsed.keyBindingJwt().get().serialize())
                .isEqualTo(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/kb_jwt_serialized.txt"));
        assertThat(parsed.issuerSignedJwt().serialize())
                .isEqualTo(FixtureLoader.readExampleCompact("sd_jwt_vcld/01/sd_jwt_jws_part.txt"));
    }

    @Test
    void rejectsAStringWithoutAnyTilde() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> SdJwtParser.parse("not-an-sd-jwt"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
