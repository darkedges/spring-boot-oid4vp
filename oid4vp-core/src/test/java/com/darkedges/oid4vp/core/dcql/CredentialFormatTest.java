package com.darkedges.oid4vp.core.dcql;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredentialFormatTest {

    @Test
    void parsesItsOwnCanonicalIdentifierForEveryFormat() {
        for (CredentialFormat format : CredentialFormat.values()) {
            assertThat(CredentialFormat.fromIdentifier(format.identifier())).isEqualTo(format);
        }
    }

    @Test
    void alsoRecognizesVcSdJwtAsAnAliasForDcSdJwt() {
        assertThat(CredentialFormat.fromIdentifier("vc+sd-jwt")).isEqualTo(CredentialFormat.DC_SD_JWT);
    }

    @Test
    void stillEmitsTheCanonicalIdentifierRegardlessOfWhichAliasWasParsed() {
        assertThat(CredentialFormat.fromIdentifier("vc+sd-jwt").identifier()).isEqualTo("dc+sd-jwt");
    }

    @Test
    void rejectsAnUnknownIdentifier() {
        assertThatThrownBy(() -> CredentialFormat.fromIdentifier("not_a_real_format"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
