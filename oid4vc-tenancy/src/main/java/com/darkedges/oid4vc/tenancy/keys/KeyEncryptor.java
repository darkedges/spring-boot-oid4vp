package com.darkedges.oid4vc.tenancy.keys;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Encrypts tenants' private keys at rest with AES-256-GCM under the deployment's key-encryption key
 * ({@code TENANT_KEY_ENCRYPTION_KEY}, 32 random bytes, base64).
 *
 * <p>Each value is bound to where it belongs (tenant and key id, as additional authenticated data), so a stored key copied onto
 * another tenant's row does not decrypt. Format: version byte {@code 1}, 12-byte nonce, ciphertext with its 16-byte tag.
 */
public final class KeyEncryptor {

    private static final byte VERSION = 1;
    private static final int NONCE_BYTES = 12;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKey key;

    public KeyEncryptor(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != 32) {
            throw new IllegalArgumentException("the key-encryption key must be 32 bytes (base64 of 32 random bytes)");
        }
        this.key = new SecretKeySpec(keyBytes.clone(), "AES");
    }

    public static KeyEncryptor fromBase64(String base64) {
        if (base64 == null || base64.isBlank()) {
            throw new IllegalArgumentException("no key-encryption key configured (oid4vc.tenancy.keys.encryption-key / TENANT_KEY_ENCRYPTION_KEY)");
        }
        return new KeyEncryptor(Base64.getDecoder().decode(base64.trim()));
    }

    /** A random key, for tests and in-memory development only: keys encrypted with it are lost with the process. */
    public static KeyEncryptor ephemeral() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return new KeyEncryptor(bytes);
    }

    public byte[] encrypt(byte[] plaintext, String tenantId, String kid) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad(tenantId, kid));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return ByteBuffer.allocate(1 + NONCE_BYTES + ciphertext.length).put(VERSION).put(nonce).put(ciphertext).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not encrypt a tenant key", e);
        }
    }

    public byte[] decrypt(byte[] stored, String tenantId, String kid) {
        if (stored == null || stored.length < 1 + NONCE_BYTES + 16 || stored[0] != VERSION) {
            throw new IllegalStateException("unreadable stored key for tenant " + tenantId + " (" + kid + ")");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Arrays.copyOfRange(stored, 1, 1 + NONCE_BYTES)));
            cipher.updateAAD(aad(tenantId, kid));
            return cipher.doFinal(stored, 1 + NONCE_BYTES, stored.length - 1 - NONCE_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("could not decrypt the stored key for tenant " + tenantId + " (" + kid
                    + "): wrong key-encryption key, or the value was moved", e);
        }
    }

    private static byte[] aad(String tenantId, String kid) {
        return ("oid4vc-tenant-key|" + tenantId + "|" + kid).getBytes(StandardCharsets.UTF_8);
    }
}
