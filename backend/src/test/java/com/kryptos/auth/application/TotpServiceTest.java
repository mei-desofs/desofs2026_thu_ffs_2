package com.kryptos.auth.application;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class TotpServiceTest {

    private final TotpService totpService = new TotpService();

    @Test
    void generateSecret_shouldGenerateValidBase64String() {
        String secret = totpService.generateSecret();

        assertNotNull(secret);
        assertFalse(secret.isBlank());
        assertTrue(secret.matches("[A-Za-z0-9+/=]+"), "Secret should be valid Base64");
    }

    @Test
    void generateSecret_shouldGenerateDifferentSecrets() {
        String secret1 = totpService.generateSecret();
        String secret2 = totpService.generateSecret();

        assertNotEquals(secret1, secret2);
    }

    @Test
    void generateQrCode_shouldGenerateValidDataUrl() {
        String secret = totpService.generateSecret();
        String qrCode = totpService.generateQrCode(secret, "testuser", "Kryptos");

        assertNotNull(qrCode);
        assertTrue(qrCode.startsWith("data:image/png;base64,"));
        assertTrue(qrCode.length() > 100);
    }

    @Test
    void generateQrCode_shouldIncludeUsernameAndIssuer() {
        String secret = totpService.generateSecret();
        String qrCode = totpService.generateQrCode(secret, "johndoe", "MyApp");

        assertNotNull(qrCode);
        assertTrue(qrCode.startsWith("data:image/png;base64,"));
    }

    @Test
    void validate_shouldReturnTrue_withValidCode() {
        String secret = totpService.generateSecret();

        long timeIndex = System.currentTimeMillis() / 1000 / 30;
        String code = generateTotpCode(secret, timeIndex);

        assertTrue(totpService.validate(secret, code));
    }

    @Test
    void validate_shouldReturnTrue_withPreviousCode() {
        String secret = totpService.generateSecret();

        long timeIndex = System.currentTimeMillis() / 1000 / 30 - 1;
        String code = generateTotpCode(secret, timeIndex);

        assertTrue(totpService.validate(secret, code));
    }

    @Test
    void validate_shouldReturnTrue_withNextCode() {
        String secret = totpService.generateSecret();

        long timeIndex = System.currentTimeMillis() / 1000 / 30 + 1;
        String code = generateTotpCode(secret, timeIndex);

        assertTrue(totpService.validate(secret, code));
    }

    @Test
    void validate_shouldReturnFalse_withInvalidCode() {
        String secret = totpService.generateSecret();

        assertFalse(totpService.validate(secret, "000000"));
        assertFalse(totpService.validate(secret, "999999"));
    }

    @Test
    void validate_shouldReturnFalse_withNullSecret() {
        assertFalse(totpService.validate(null, "123456"));
    }

    @Test
    void validate_shouldReturnFalse_withNullCode() {
        String secret = totpService.generateSecret();
        assertFalse(totpService.validate(secret, null));
    }

    private String generateTotpCode(String secret, long timeIndex) {
        try {
            byte[] secretBytes = java.util.Base64.getDecoder().decode(secret);
            byte[] timeBytes = new byte[8];
            for (int i = 7; i >= 0; i--) {
                timeBytes[i] = (byte) (timeIndex & 0xFF);
                timeIndex >>= 8;
            }

            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
            mac.init(new javax.crypto.spec.SecretKeySpec(secretBytes, 0, secretBytes.length, "HmacSHA1"));
            byte[] hash = mac.doFinal(timeBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int truncated = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset + 1] & 0xFF) << 16) |
                    ((hash[offset + 2] & 0xFF) << 8) |
                    (hash[offset + 3] & 0xFF);

            int code = truncated % 1000000;
            return String.format("%06d", code);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate TOTP code", e);
        }
    }
}
