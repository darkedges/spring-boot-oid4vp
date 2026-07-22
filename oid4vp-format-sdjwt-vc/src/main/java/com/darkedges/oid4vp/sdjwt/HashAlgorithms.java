package com.darkedges.oid4vp.sdjwt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Maps IANA "Named Information Hash Algorithm" registry "Hash Name String" identifiers (e.g.
 * {@code "sha-256"}, as used in {@code _sd_alg} and {@code transaction_data_hashes_alg}) to
 * {@link MessageDigest} algorithm names.
 */
final class HashAlgorithms {

    private HashAlgorithms() {}

    static final String DEFAULT = "sha-256";

    static MessageDigest newDigest(String hashNameString) {
        String javaName = switch (hashNameString) {
            case "sha-256" -> "SHA-256";
            case "sha-384" -> "SHA-384";
            case "sha-512" -> "SHA-512";
            default -> throw new IllegalArgumentException("unsupported hash algorithm: " + hashNameString);
        };
        try {
            return MessageDigest.getInstance(javaName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
