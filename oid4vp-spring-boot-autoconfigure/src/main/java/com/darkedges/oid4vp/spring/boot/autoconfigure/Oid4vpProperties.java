package com.darkedges.oid4vp.spring.boot.autoconfigure;

import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationResponseAuthenticationFilter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {@code oid4vp.verifier.*} configuration properties, shaped after {@code OAuth2ClientProperties}.
 *
 * <p>{@code dcql-query} and {@code client-metadata} are configured as raw JSON text rather than nested
 * YAML/properties keys: the DCQL/client-metadata domain model (sealed interfaces, {@code Optional}
 * fields) doesn't map cleanly onto Spring Boot's relaxed property binder, and JSON is DCQL's own native
 * wire format anyway.
 */
@ConfigurationProperties(prefix = "oid4vp.verifier")
public class Oid4vpProperties {

    /** Keyed by registration id, e.g. {@code oid4vp.verifier.relying-party.demo.client-id=...}. */
    private Map<String, RelyingParty> relyingParty = new LinkedHashMap<>();

    /** How long an issued Authorization Request's context is kept while awaiting the Wallet's response. */
    private Duration requestTtl = Duration.ofMinutes(10);

    /** Ant/PathPattern-style path for the {@code direct_post} response endpoint. */
    private String responseUriPattern = Oid4vpAuthorizationResponseAuthenticationFilter.DEFAULT_RESPONSE_URI_PATTERN;

    public Map<String, RelyingParty> getRelyingParty() {
        return relyingParty;
    }

    public void setRelyingParty(Map<String, RelyingParty> relyingParty) {
        this.relyingParty = relyingParty;
    }

    public Duration getRequestTtl() {
        return requestTtl;
    }

    public void setRequestTtl(Duration requestTtl) {
        this.requestTtl = requestTtl;
    }

    public String getResponseUriPattern() {
        return responseUriPattern;
    }

    public void setResponseUriPattern(String responseUriPattern) {
        this.responseUriPattern = responseUriPattern;
    }

    public static class RelyingParty {

        /** The Verifier's own {@code client_id}, including any Client Identifier Prefix, e.g.
         * {@code redirect_uri:https://verifier.example.org/oid4vp/response}. */
        private String clientId;

        private String responseUri;

        /** {@code response_mode}, e.g. {@code direct_post} (default) or {@code direct_post.jwt} — the
         * latter requires {@code client-metadata} to carry a response-encryption {@code jwks} entry. */
        private String responseMode = "direct_post";

        /** The {@code dcql_query} value, as JSON text. */
        private String dcqlQuery;

        /** OPTIONAL {@code client_metadata} value, as JSON text. */
        private String clientMetadata;

        /** OPTIONAL fixed Wallet {@code authorization_endpoint} to redirect the End-User's browser to —
         * see {@code Oid4vpRelyingPartyRegistration.walletAuthorizationEndpoint}. */
        private String walletAuthorizationEndpoint;

        /** OPTIONAL {@code verifier_info} value (a JSON array of attestations), as JSON text. */
        private String verifierInfo;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getResponseUri() {
            return responseUri;
        }

        public void setResponseUri(String responseUri) {
            this.responseUri = responseUri;
        }

        public String getResponseMode() {
            return responseMode;
        }

        public void setResponseMode(String responseMode) {
            this.responseMode = responseMode;
        }

        public String getDcqlQuery() {
            return dcqlQuery;
        }

        public void setDcqlQuery(String dcqlQuery) {
            this.dcqlQuery = dcqlQuery;
        }

        public String getClientMetadata() {
            return clientMetadata;
        }

        public void setClientMetadata(String clientMetadata) {
            this.clientMetadata = clientMetadata;
        }

        public String getWalletAuthorizationEndpoint() {
            return walletAuthorizationEndpoint;
        }

        public void setWalletAuthorizationEndpoint(String walletAuthorizationEndpoint) {
            this.walletAuthorizationEndpoint = walletAuthorizationEndpoint;
        }

        public String getVerifierInfo() {
            return verifierInfo;
        }

        public void setVerifierInfo(String verifierInfo) {
            this.verifierInfo = verifierInfo;
        }
    }
}
