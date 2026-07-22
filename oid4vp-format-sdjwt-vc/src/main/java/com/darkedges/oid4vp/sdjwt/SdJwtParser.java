package com.darkedges.oid4vp.sdjwt;

import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Parses the {@code ~}-joined SD-JWT serialization: {@code <Issuer-signed JWT>~<Disclosure>~...~} for an
 * Issuance-form SD-JWT (trailing {@code ~}, no Key Binding JWT), or
 * {@code <Issuer-signed JWT>~<Disclosure>~...~<KB-JWT>} for a Presentation-form SD-JWT+KB.
 */
public final class SdJwtParser {

    private SdJwtParser() {}

    public static SdJwt parse(String serialized) {
        if (serialized == null || !serialized.contains("~")) {
            throw new IllegalArgumentException("not a valid SD-JWT serialization (missing '~'): " + serialized);
        }
        String[] parts = serialized.split("~", -1);

        SignedJWT issuerSignedJwt = parseJwt(parts[0], "issuer-signed JWT");

        String lastPart = parts[parts.length - 1];
        List<String> disclosureParts = Arrays.asList(parts).subList(1, parts.length - 1);
        List<Disclosure> disclosures = disclosureParts.stream().map(Disclosure::parse).toList();

        Optional<SignedJWT> keyBindingJwt =
                lastPart.isEmpty() ? Optional.empty() : Optional.of(parseJwt(lastPart, "Key Binding JWT"));

        return new SdJwt(issuerSignedJwt, disclosures, keyBindingJwt);
    }

    private static SignedJWT parseJwt(String compact, String what) {
        try {
            return SignedJWT.parse(compact);
        } catch (ParseException e) {
            throw new IllegalArgumentException("failed to parse " + what + ": " + compact, e);
        }
    }
}
