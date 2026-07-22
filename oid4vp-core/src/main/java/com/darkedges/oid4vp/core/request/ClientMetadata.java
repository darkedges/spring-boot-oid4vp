package com.darkedges.oid4vp.core.request;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The {@code client_metadata} Authorization Request parameter / Verifier (Client) Metadata.
 *
 * <p>{@code jwks} is kept as a raw {@link JsonNode} (a JWK Set) rather than a parsed key type, since this
 * module has no cryptographic dependency; callers that need actual key material (e.g. to encrypt a
 * response) parse it with whatever JOSE library the format module uses.
 *
 * @param jwks                                 OPTIONAL JWK Set, for response encryption keys.
 * @param encryptedResponseEncValuesSupported  OPTIONAL supported JWE {@code enc} algorithms; per spec,
 *                                             defaults to {@code ["A128GCM"]} when absent and non-HPKE
 *                                             encryption is used.
 * @param vpFormatsSupported                  REQUIRED-when-not-otherwise-known format capability map.
 */
public record ClientMetadata(
        Optional<JsonNode> jwks,
        List<String> encryptedResponseEncValuesSupported,
        Map<CredentialFormat, JsonNode> vpFormatsSupported) {

    public ClientMetadata {
        jwks = jwks == null ? Optional.empty() : jwks;
        encryptedResponseEncValuesSupported =
                encryptedResponseEncValuesSupported == null ? List.of() : List.copyOf(encryptedResponseEncValuesSupported);
        vpFormatsSupported = vpFormatsSupported == null ? Map.of() : Map.copyOf(vpFormatsSupported);
    }

    public List<String> encryptedResponseEncValuesSupportedOrDefault() {
        return encryptedResponseEncValuesSupported.isEmpty() ? List.of("A128GCM") : encryptedResponseEncValuesSupported;
    }
}
