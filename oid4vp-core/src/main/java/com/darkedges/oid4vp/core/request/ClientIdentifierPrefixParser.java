package com.darkedges.oid4vp.core.request;

/**
 * Parses the syntax {@code <client_id_prefix>:<orig_client_id>} of a {@code client_id} value (OpenID4VP
 * 1.1, "Client Identifier Prefix and Verifier Metadata Management"). Splits on the first colon only, so
 * that prefixed values which themselves contain colons (e.g. a DID) are preserved intact.
 *
 * <p>This is syntax parsing only — it does not validate that the claimed prefix is legitimate (no
 * signature/certificate/DID/trust-chain checks); see {@link ClientIdentifierPrefix}'s class doc.
 */
public final class ClientIdentifierPrefixParser {

    private ClientIdentifierPrefixParser() {}

    public static ClientIdentifierPrefix parse(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("client_id must not be blank");
        }

        int colonIndex = clientId.indexOf(':');
        if (colonIndex < 0) {
            return new ClientIdentifierPrefix.PreRegistered(clientId);
        }

        String prefix = clientId.substring(0, colonIndex);
        String rest = clientId.substring(colonIndex + 1);

        return switch (prefix) {
            case "redirect_uri" -> new ClientIdentifierPrefix.RedirectUri(rest);
            case "openid_federation" -> new ClientIdentifierPrefix.OpenidFederation(rest);
            case "decentralized_identifier" -> new ClientIdentifierPrefix.DecentralizedIdentifier(rest);
            case "verifier_attestation" -> new ClientIdentifierPrefix.VerifierAttestation(rest);
            case "x509_san_dns" -> new ClientIdentifierPrefix.X509SanDns(rest);
            case "x509_hash" -> new ClientIdentifierPrefix.X509Hash(rest);
            case "origin" -> new ClientIdentifierPrefix.Origin(rest);
            // Fallback: unrecognized prefix token — the *entire* original value (colon included) is the
            // pre-registered client id, per the spec's Fallback rule.
            default -> new ClientIdentifierPrefix.PreRegistered(clientId);
        };
    }
}
