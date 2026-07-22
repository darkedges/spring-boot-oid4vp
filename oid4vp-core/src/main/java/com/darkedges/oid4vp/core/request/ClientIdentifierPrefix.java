package com.darkedges.oid4vp.core.request;

/**
 * A {@code client_id}, decomposed into its Client Identifier Prefix (if any) and the remaining value.
 * See OpenID4VP 1.1, "Client Identifier Prefix and Verifier Metadata Management".
 *
 * <p>Only parsing (syntax) is implemented in this phase — see {@link ClientIdentifierPrefixParser}. The
 * validators that would verify a claimed prefix is legitimate (signature/X.509 chain checks for
 * {@code x509_san_dns}/{@code x509_hash}, DID resolution for {@code decentralized_identifier}, trust
 * chain resolution for {@code openid_federation}, attestation JWT verification for
 * {@code verifier_attestation}) are Wallet-side request-validation concerns deferred to a later phase;
 * this phase's Verifier {@code AuthenticationProvider} only needs to know its own {@code client_id}.
 */
public sealed interface ClientIdentifierPrefix {

    /** The full client_id string, including the prefix (if any), exactly as it MUST always be used
     * internally and in presentations (OpenID4VP 1.1, "Always Use the Full Client Identifier"). */
    String fullClientId();

    /** Fallback: no recognized prefix precedes a colon, or there is no colon at all — treated as a
     * pre-registered client (RFC6749 default). */
    record PreRegistered(String clientId) implements ClientIdentifierPrefix {
        public PreRegistered {
            requireNonBlank(clientId, "clientId");
        }

        @Override
        public String fullClientId() {
            return clientId;
        }
    }

    record RedirectUri(String value) implements ClientIdentifierPrefix {
        public RedirectUri {
            requireNonBlank(value, "value");
        }

        @Override
        public String fullClientId() {
            return "redirect_uri:" + value;
        }
    }

    record OpenidFederation(String entityIdentifier) implements ClientIdentifierPrefix {
        public OpenidFederation {
            requireNonBlank(entityIdentifier, "entityIdentifier");
        }

        @Override
        public String fullClientId() {
            return "openid_federation:" + entityIdentifier;
        }
    }

    record DecentralizedIdentifier(String did) implements ClientIdentifierPrefix {
        public DecentralizedIdentifier {
            requireNonBlank(did, "did");
        }

        @Override
        public String fullClientId() {
            return "decentralized_identifier:" + did;
        }
    }

    record VerifierAttestation(String clientIdentifier) implements ClientIdentifierPrefix {
        public VerifierAttestation {
            requireNonBlank(clientIdentifier, "clientIdentifier");
        }

        @Override
        public String fullClientId() {
            return "verifier_attestation:" + clientIdentifier;
        }
    }

    record X509SanDns(String dnsName) implements ClientIdentifierPrefix {
        public X509SanDns {
            requireNonBlank(dnsName, "dnsName");
        }

        @Override
        public String fullClientId() {
            return "x509_san_dns:" + dnsName;
        }
    }

    record X509Hash(String base64UrlSha256) implements ClientIdentifierPrefix {
        public X509Hash {
            requireNonBlank(base64UrlSha256, "base64UrlSha256");
        }

        @Override
        public String fullClientId() {
            return "x509_hash:" + base64UrlSha256;
        }
    }

    /** Reserved for the Digital Credentials API's implicit audience binding; Wallets MUST NOT accept
     * this prefix in a Verifier-supplied {@code client_id} — it is derived from the browser Origin, never
     * client-supplied. Modeled here only so {@code switch} expressions over this interface are exhaustive. */
    record Origin(String origin) implements ClientIdentifierPrefix {
        public Origin {
            requireNonBlank(origin, "origin");
        }

        @Override
        public String fullClientId() {
            return "origin:" + origin;
        }
    }

    private static void requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
