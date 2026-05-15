package com.kryptos.shared.encryption;

import com.kryptos.shared.exception.EncryptionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionServiceTest {

    private static final String TEST_SECRET = "this-is-a-test-secret-that-is-long-enough-32-chars!";

    private EncryptionService encryptionService;

    @BeforeEach
    void setUp() {
        encryptionService = new EncryptionService(TEST_SECRET);
    }

    @Test
    void encrypt_shouldReturnBase64String_whenGivenPlaintext() {
        String ciphertext = encryptionService.encrypt("my-secret-password");
        assertNotNull(ciphertext);
        assertFalse(ciphertext.isBlank());
        assertDoesNotThrow(() -> java.util.Base64.getDecoder().decode(ciphertext));
    }

    @Test
    void decrypt_shouldReturnOriginalPlaintext_whenGivenCiphertext() {
        String plaintext = "my-secret-password-123!";
        String ciphertext = encryptionService.encrypt(plaintext);
        String decrypted = encryptionService.decrypt(ciphertext);
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
        String shortCiphertext = java.util.Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        assertThrows(EncryptionException.class, () -> encryptionService.decrypt(shortCiphertext));
    }

    @Test
    void constructor_shouldThrow_whenSecretIsBlank() {
        assertThrows(IllegalStateException.class, () -> new EncryptionService(""));
        assertThrows(IllegalStateException.class, () -> new EncryptionService("   "));
    }

    @Test
    void decrypt_shouldThrowEncryptionException_whenCiphertextIsTampered() {
        String ciphertext = encryptionService.encrypt("secret");
        byte[] decoded = java.util.Base64.getDecoder().decode(ciphertext);
        decoded[decoded.length - 1] ^= (byte) 0xFF;
        String tampered = java.util.Base64.getEncoder().encodeToString(decoded);
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
