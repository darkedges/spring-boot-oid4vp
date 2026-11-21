package com.darkedges.oid4vp.verifier.jdbc;

import org.springframework.jdbc.core.simple.JdbcClient;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The table {@code oid4vp_verifier_entry}, shared by the stores here, one {@code kind} each.
 *
 * <ul>
 *   <li>Keys and owners are stored as their SHA-256: a {@code state}, a transaction id and a response code are bearer secrets.</li>
 *   <li>Payloads (a verified presentation is someone's identity) are encrypted with AES-256-GCM, bound to their kind and key.</li>
 *   <li>{@link #take} removes and returns an entry only for its owner, in one statement, so it is used once, and never by the wrong
 *       registration or with the wrong code; a mismatch leaves the entry for its rightful use.</li>
 * </ul>
 * Expiry is compared with the application's clock. Expired rows are swept now and then as entries are added.
 */
public final class VerifierEntryTable {

    public record Entry(byte[] payload, Instant expiresAt) {}

    private static final byte VERSION = 1;
    private static final int NONCE_BYTES = 12;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int SWEEP_EVERY = 200;

    private final JdbcClient jdbc;
    private final SecretKeySpec key;
    private final AtomicLong writes = new AtomicLong();

    public VerifierEntryTable(JdbcClient jdbc, byte[] encryptionKey) {
        if (encryptionKey == null || encryptionKey.length != 32) {
            throw new IllegalArgumentException("oid4vp.verifier.store.encryption-key must be base64 of 32 random bytes");
        }
        this.jdbc = jdbc;
        this.key = new SecretKeySpec(encryptionKey.clone(), "AES");
    }

    public static VerifierEntryTable create(JdbcClient jdbc, String base64EncryptionKey) {
        if (base64EncryptionKey == null || base64EncryptionKey.isBlank()) {
            throw new IllegalArgumentException("oid4vp.verifier.store.encryption-key is required for the jdbc store "
                    + "(base64 of 32 random bytes): the stores hold verified identity claims");
        }
        return new VerifierEntryTable(jdbc, Base64.getDecoder().decode(base64EncryptionKey.trim()));
    }

    public void put(String kind, String key, String owner, byte[] payload, Instant expiresAt) {
        String hashedKey = hash(key);
        jdbc.sql("""
                INSERT INTO oid4vp_verifier_entry (kind, key, owner, payload, expires_at) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (kind, key) DO UPDATE SET owner = EXCLUDED.owner, payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at
                """).params(kind, hashedKey, hash(owner), encrypt(payload, kind, hashedKey), Timestamp.from(expiresAt)).update();
        if (writes.incrementAndGet() % SWEEP_EVERY == 0) sweep();
    }

    /** Removes and returns the entry if {@code owner} is its owner; otherwise leaves it. */
    public Optional<Entry> take(String kind, String key, String owner) {
        String hashedKey = hash(key);
        return jdbc.sql("DELETE FROM oid4vp_verifier_entry WHERE kind = ? AND key = ? AND owner = ? RETURNING payload, expires_at")
                .params(kind, hashedKey, hash(owner))
                .query((rs, row) -> new Entry(decrypt(rs.getBytes("payload"), kind, hashedKey), rs.getTimestamp("expires_at").toInstant()))
                .optional();
    }

    /** Removes and returns the entry whoever its owner: for callers that don't know the owner. */
    public Optional<Entry> takeAny(String kind, String key) {
        String hashedKey = hash(key);
        return jdbc.sql("DELETE FROM oid4vp_verifier_entry WHERE kind = ? AND key = ? RETURNING payload, expires_at")
                .params(kind, hashedKey)
                .query((rs, row) -> new Entry(decrypt(rs.getBytes("payload"), kind, hashedKey), rs.getTimestamp("expires_at").toInstant()))
                .optional();
    }

    /** Every unexpired entry of this owner. */
    public List<byte[]> ofOwner(String kind, String owner, Instant now) {
        return jdbc.sql("SELECT key, payload FROM oid4vp_verifier_entry WHERE kind = ? AND owner = ? AND expires_at > ?")
                .params(kind, hash(owner), Timestamp.from(now))
                .query((rs, row) -> decrypt(rs.getBytes("payload"), kind, rs.getString("key")))
                .list();
    }

    /** Deletes every entry that expired over five minutes ago (a margin for clocks that disagree). Returns how many. */
    public int sweep() {
        return jdbc.sql("DELETE FROM oid4vp_verifier_entry WHERE expires_at < now() - interval '5 minutes'").update();
    }

    static String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] encrypt(byte[] plaintext, String kind, String hashedKey) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad(kind, hashedKey));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(1 + NONCE_BYTES + ciphertext.length).put(VERSION).put(nonce).put(ciphertext).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not encrypt a verifier entry", e);
        }
    }

    private byte[] decrypt(byte[] stored, String kind, String hashedKey) {
        if (stored == null || stored.length < 1 + NONCE_BYTES + 16 || stored[0] != VERSION) throw new IllegalStateException("unreadable verifier entry");
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Arrays.copyOfRange(stored, 1, 1 + NONCE_BYTES)));
            cipher.updateAAD(aad(kind, hashedKey));
            return cipher.doFinal(stored, 1 + NONCE_BYTES, stored.length - 1 - NONCE_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not decrypt a verifier entry: wrong oid4vp.verifier.store.encryption-key, or the row was moved", e);
        }
    }

    private static byte[] aad(String kind, String hashedKey) {
        return ("oid4vp-verifier-entry|" + kind + "|" + hashedKey).getBytes(StandardCharsets.UTF_8);
    }
}
