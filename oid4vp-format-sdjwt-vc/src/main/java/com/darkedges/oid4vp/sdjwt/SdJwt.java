package com.darkedges.oid4vp.sdjwt;

import com.nimbusds.jwt.SignedJWT;

import java.util.List;
import java.util.Optional;

/**
 * A parsed SD-JWT: the Issuer-signed JWT, its Disclosures, and (for a presentation) an appended Key
 * Binding JWT.
 */
public record SdJwt(SignedJWT issuerSignedJwt, List<Disclosure> disclosures, Optional<SignedJWT> keyBindingJwt) {

    public SdJwt {
        if (issuerSignedJwt == null) {
            throw new IllegalArgumentException("issuerSignedJwt is required");
        }
        disclosures = disclosures == null ? List.of() : List.copyOf(disclosures);
        keyBindingJwt = keyBindingJwt == null ? Optional.empty() : keyBindingJwt;
    }

    /**
     * The Issuer-signed JWT plus its Disclosures, each separated by (and ending with) a tilde — i.e.
     * the whole serialized SD-JWT minus a trailing Key Binding JWT. This is exactly the input a KB-JWT's
     * {@code sd_hash} is computed over.
     */
    public String toStringWithoutKeyBinding() {
        StringBuilder sb = new StringBuilder(issuerSignedJwt.serialize()).append('~');
        for (Disclosure disclosure : disclosures) {
            sb.append(disclosure.rawBase64Url()).append('~');
        }
        return sb.toString();
    }

    public String serialize() {
        String base = toStringWithoutKeyBinding();
        return keyBindingJwt.map(kb -> base + kb.serialize()).orElse(base);
    }
}
