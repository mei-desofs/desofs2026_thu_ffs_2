package com.kryptos.shared.encryption;

import com.kryptos.shared.exception.EncryptionException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

@Service
public final class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 128;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecretKey primaryKeyV2;
    private final SecretKey primaryKeyV1;
    private SecretKey previousKeyV2;
    private SecretKey previousKeyV1;

    public EncryptionService(
            @Value("${kryptos.encryption.secret}") String encryptionSecret,
            @Value("${kryptos.encryption.salt:default-kryptos-salt-value-must-be-changed}") String encryptionSalt,
            @Value("${kryptos.encryption.previous-secret:#{null}}") String previousSecret) {

        if (encryptionSecret == null || encryptionSecret.isBlank()) {
            throw new IllegalStateException("kryptos.encryption.secret must be configured");
        }

        this.primaryKeyV1 = deriveKeyV1(encryptionSecret);
        this.primaryKeyV2 = deriveKeyV2(encryptionSecret, encryptionSalt);

        if (previousSecret != null && !previousSecret.isBlank()) {
            this.previousKeyV1 = deriveKeyV1(previousSecret);
            this.previousKeyV2 = deriveKeyV2(previousSecret, encryptionSalt);
        }
    }

    private SecretKey deriveKeyV1(String secret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(secret.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(keyBytes, "AES");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private SecretKey deriveKeyV2(String secret, String salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            return new SecretKeySpec(tmp.getEncoded(), "AES");
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 not available", e);
        }
    }

    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        try {
            byte[] iv = new byte[IV_LENGTH];
            SECURE_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, primaryKeyV2, new GCMParameterSpec(TAG_LENGTH, iv));

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] encrypted = ByteBuffer.allocate(IV_LENGTH + ciphertext.length)
                    .put(iv)
                    .put(ciphertext)
                    .array();

            return "v2$" + Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new EncryptionException("Failed to encrypt data", e);
        }
    }

    public String decrypt(String ciphertext) {
        if (ciphertext == null) {
            return null;
        }
        
        try {
            if (ciphertext.startsWith("v2$")) {
                String base64Data = ciphertext.substring(3);
                return attemptDecryption(base64Data, primaryKeyV2, previousKeyV2);
            } else if (ciphertext.startsWith("v1$")) {
                String base64Data = ciphertext.substring(3);
                return attemptDecryption(base64Data, primaryKeyV1, previousKeyV1);
            } else {
                // Legacy data without prefix
                return attemptDecryption(ciphertext, primaryKeyV1, previousKeyV1);
            }
        } catch (Exception e) {
            throw new EncryptionException("Failed to decrypt data", e);
        }
    }

    private String attemptDecryption(String base64Data, SecretKey primaryKey, SecretKey fallbackKey) throws Exception {
        try {
            return doDecrypt(base64Data, primaryKey);
        } catch (Exception e) {
            if (fallbackKey != null) {
                try {
                    return doDecrypt(base64Data, fallbackKey);
                } catch (Exception fallbackEx) {
                    throw new EncryptionException("Failed to decrypt with both primary and fallback keys", fallbackEx);
                }
            }
            throw e;
        }
    }

    private String doDecrypt(String base64Data, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(base64Data);
        ByteBuffer buffer = ByteBuffer.wrap(decoded);

        byte[] iv = new byte[IV_LENGTH];
        buffer.get(iv);

        byte[] encryptedData = new byte[buffer.remaining()];
        buffer.get(encryptedData);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH, iv));

        byte[] plaintext = cipher.doFinal(encryptedData);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}
