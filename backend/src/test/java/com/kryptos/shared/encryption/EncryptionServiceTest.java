package com.kryptos.shared.encryption;

import com.kryptos.shared.exception.EncryptionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionServiceTest {

    private static final String TEST_SECRET = "this-is-a-test-secret-that-is-long-enough-32-chars!";
    private static final String TEST_SALT = "test-salt";
    private static final String PREVIOUS_SECRET = "old-test-secret-that-is-long-enough-32-chars!";

    private EncryptionService encryptionService;

    @BeforeEach
    void setUp() {
        encryptionService = new EncryptionService(TEST_SECRET, TEST_SALT, PREVIOUS_SECRET);
    }

    @Test
    void encrypt_shouldReturnV2PrefixedBase64String_whenGivenPlaintext() {
        String ciphertext = encryptionService.encrypt("my-secret-password");
        assertNotNull(ciphertext);
        assertFalse(ciphertext.isBlank());
        assertTrue(ciphertext.startsWith("v2$"));
        String base64part = ciphertext.substring(3);
        assertDoesNotThrow(() -> java.util.Base64.getDecoder().decode(base64part));
    }

    @Test
    void decrypt_shouldReturnOriginalPlaintext_whenGivenV2Ciphertext() {
        String plaintext = "my-secret-password-123!";
        String ciphertext = encryptionService.encrypt(plaintext);
        String decrypted = encryptionService.decrypt(ciphertext);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void decrypt_shouldDecryptV1LegacyCiphertext() {
        EncryptionService legacyService = new EncryptionService(TEST_SECRET, TEST_SALT, null);
        String plaintext = "legacy-password";
        
        // Emulate V1 encryption manually (SHA-256)
        String v1Ciphertext;
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(TEST_SECRET.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            javax.crypto.SecretKey key = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
            
            byte[] iv = new byte[12];
            new java.security.SecureRandom().nextBytes(iv);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.GCMParameterSpec(128, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] encrypted = java.nio.ByteBuffer.allocate(12 + ciphertext.length).put(iv).put(ciphertext).array();
            v1Ciphertext = java.util.Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        // Should decrypt implicitly without prefix
        String decryptedImplicit = encryptionService.decrypt(v1Ciphertext);
        assertEquals(plaintext, decryptedImplicit);
        
        // Should decrypt with v1$ prefix
        String decryptedExplicit = encryptionService.decrypt("v1$" + v1Ciphertext);
        assertEquals(plaintext, decryptedExplicit);
    }

    @Test
    void decrypt_shouldFallbackToPreviousSecret() {
        EncryptionService oldService = new EncryptionService(PREVIOUS_SECRET, TEST_SALT, null);
        String plaintext = "old-key-password";
        String oldCiphertext = oldService.encrypt(plaintext);
        
        // Current service should decrypt old ciphertext because it falls back to previousSecret
        String decrypted = encryptionService.decrypt(oldCiphertext);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void encrypt_and_decrypt_shouldHandleSpecialCharacters() {
        String plaintext = "P@ssw0rd! #$% &*()[]{}|;:',.<>?/~`";
        String ciphertext = encryptionService.encrypt(plaintext);
        String decrypted = encryptionService.decrypt(ciphertext);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void encrypt_and_decrypt_shouldHandleEmptyString() {
        String plaintext = "";
        String ciphertext = encryptionService.encrypt(plaintext);
        String decrypted = encryptionService.decrypt(ciphertext);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void encrypt_and_decrypt_shouldHandleLongString() {
        String plaintext = "a".repeat(10000);
        String ciphertext = encryptionService.encrypt(plaintext);
        String decrypted = encryptionService.decrypt(ciphertext);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void encrypt_shouldReturnNull_whenGivenNull() {
        assertNull(encryptionService.encrypt(null));
    }

    @Test
    void decrypt_shouldReturnNull_whenGivenNull() {
        assertNull(encryptionService.decrypt(null));
    }

    @Test
    void encrypt_shouldProduceDifferentCiphertexts_forSamePlaintext() {
        String plaintext = "same-password";
        String ciphertext1 = encryptionService.encrypt(plaintext);
        String ciphertext2 = encryptionService.encrypt(plaintext);
        assertNotEquals(ciphertext1, ciphertext2);
    }

    @Test
    void decrypt_shouldThrowEncryptionException_whenCiphertextIsInvalid() {
        assertThrows(EncryptionException.class, () -> encryptionService.decrypt("invalid-base64!!"));
    }

    @Test
    void decrypt_shouldThrowEncryptionException_whenCiphertextIsTooShort() {
        String shortCiphertext = "v2$" + java.util.Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        assertThrows(EncryptionException.class, () -> encryptionService.decrypt(shortCiphertext));
    }

    @Test
    void constructor_shouldThrow_whenSecretIsBlank() {
        assertThrows(IllegalStateException.class, () -> new EncryptionService("", TEST_SALT, PREVIOUS_SECRET));
        assertThrows(IllegalStateException.class, () -> new EncryptionService("   ", TEST_SALT, PREVIOUS_SECRET));
    }

    @Test
    void decrypt_shouldThrowEncryptionException_whenCiphertextIsTampered() {
        String ciphertext = encryptionService.encrypt("secret");
        String base64part = ciphertext.substring(3);
        byte[] decoded = java.util.Base64.getDecoder().decode(base64part);
        decoded[decoded.length - 1] ^= (byte) 0xFF;
        String tampered = "v2$" + java.util.Base64.getEncoder().encodeToString(decoded);
        assertThrows(EncryptionException.class, () -> encryptionService.decrypt(tampered));
    }

    @Test
    void encrypt_and_decrypt_shouldHandleUnicodeCharacters() {
        String plaintext = "Senha 🔐 segura 密码 ñãõ";
        String ciphertext = encryptionService.encrypt(plaintext);
        String decrypted = encryptionService.decrypt(ciphertext);
        assertEquals(plaintext, decrypted);
    }
}
