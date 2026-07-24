package com.darkedges.oid4vp.core.request;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ResponseModeTest {

    @Test
    void queryIsImplementedForTheAuthorizationCodeGrant() {
        assertThat(ResponseMode.QUERY.isImplemented()).isTrue();
        ResponseMode.QUERY.requireImplemented(); // does not throw
    }

    @Test
    void fragmentIsStillNotImplemented() {
        assertThat(ResponseMode.FRAGMENT.isImplemented()).isFalse();
        assertThatThrownBy(ResponseMode.FRAGMENT::requireImplemented).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void directPostFamilyAndDcApiFamilyRemainImplemented() {
        assertThat(ResponseMode.DIRECT_POST.isImplemented()).isTrue();
        assertThat(ResponseMode.DIRECT_POST_JWT.isImplemented()).isTrue();
        assertThat(ResponseMode.DC_API.isImplemented()).isTrue();
        assertThat(ResponseMode.DC_API_JWT.isImplemented()).isTrue();
    }
}
