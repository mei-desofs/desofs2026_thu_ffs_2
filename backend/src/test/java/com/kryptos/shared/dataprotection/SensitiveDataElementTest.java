package com.kryptos.shared.dataprotection;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class SensitiveDataElementTest {

    @Test
    void allElementsShouldHaveNonNullFieldPath() {
        for (SensitiveDataElement element : SensitiveDataElement.values()) {
            assertNotNull(element.getFieldPath(), "Field path should not be null for " + element.name());
            assertFalse(element.getFieldPath().isBlank(), "Field path should not be blank for " + element.name());
        }
    }

    @Test
    void allElementsShouldHaveNonNullDescription() {
        for (SensitiveDataElement element : SensitiveDataElement.values()) {
            assertNotNull(element.getDescription(), "Description should not be null for " + element.name());
            assertFalse(element.getDescription().isBlank(), "Description should not be blank for " + element.name());
        }
    }

    @Test
    void allElementsShouldHaveNonNullClassification() {
        for (SensitiveDataElement element : SensitiveDataElement.values()) {
            assertNotNull(element.getClassification(), "Classification should not be null for " + element.name());
        }
    }

    @Test
    void fieldPathsShouldBeUnique() {
        Set<String> paths = new HashSet<>();
        for (SensitiveDataElement element : SensitiveDataElement.values()) {
            assertTrue(paths.add(element.getFieldPath()),
                    "Duplicate field path: " + element.getFieldPath());
        }
    }

    @Test
    void fieldPathsShouldUseDotNotation() {
        for (SensitiveDataElement element : SensitiveDataElement.values()) {
            assertTrue(element.getFieldPath().contains("."),
                    "Field path should use dot notation: " + element.getFieldPath());
        }
    }

    @Test
    void encryptedPasswordShouldBeConfidential() {
        assertEquals(DataClassification.CONFIDENTIAL,
                SensitiveDataElement.CREDENTIAL_ENCRYPTED_PASSWORD.getClassification());
    }

    @Test
    void encryptionSecretShouldBeRestricted() {
        assertEquals(DataClassification.RESTRICTED,
                SensitiveDataElement.ENCRYPTION_SECRET.getClassification());
    }

    @Test
    void jwtTokenShouldBeConfidentialBecausePayloadIsOnlyEncoded() {
        assertEquals(DataClassification.CONFIDENTIAL,
                SensitiveDataElement.JWT_TOKEN.getClassification());
        String description = SensitiveDataElement.JWT_TOKEN.getDescription();
        assertTrue(description.contains("Base64"), "JWT description should mention Base64 encoding");
    }

    @Test
    void userPasswordHashShouldBeRestricted() {
        assertEquals(DataClassification.RESTRICTED,
                SensitiveDataElement.USER_PASSWORD_HASH.getClassification());
    }

    @Test
    void serviceNameShouldBePublic() {
        assertEquals(DataClassification.PUBLIC,
                SensitiveDataElement.CREDENTIAL_SERVICE_NAME.getClassification());
    }

    @Test
    void usernameShouldBeInternal() {
        assertEquals(DataClassification.INTERNAL,
                SensitiveDataElement.USER_USERNAME.getClassification());
    }

    @Test
    void emailShouldBeInternal() {
        assertEquals(DataClassification.INTERNAL,
                SensitiveDataElement.USER_EMAIL.getClassification());
    }

    @Test
    void databasePasswordShouldBeRestricted() {
        assertEquals(DataClassification.RESTRICTED,
                SensitiveDataElement.DATABASE_PASSWORD.getClassification());
    }

    @Test
    void hmacSecretShouldBeRestricted() {
        assertEquals(DataClassification.RESTRICTED,
                SensitiveDataElement.HMAC_SHARED_SECRET.getClassification());
    }

    @Test
    void jwtSigningSecretShouldBeRestricted() {
        assertEquals(DataClassification.RESTRICTED,
                SensitiveDataElement.JWT_SIGNING_SECRET.getClassification());
    }

    @Test
    void twoFACodeShouldBeConfidential() {
        assertEquals(DataClassification.CONFIDENTIAL,
                SensitiveDataElement.USER_TWO_FA_CODE.getClassification());
    }

    @Test
    void resetTokenShouldBeConfidential() {
        assertEquals(DataClassification.CONFIDENTIAL,
                SensitiveDataElement.USER_RESET_TOKEN.getClassification());
    }

    @Test
    void base64CiphertextShouldBeConfidential() {
        assertEquals(DataClassification.CONFIDENTIAL,
                SensitiveDataElement.ENCRYPTED_DATA_BASE64.getClassification());
    }

    @Test
    void hmacSignatureShouldBeConfidential() {
        assertEquals(DataClassification.CONFIDENTIAL,
                SensitiveDataElement.HMAC_SIGNATURE.getClassification());
    }

    @Test
    void allDataElementsShouldHaveValidGroupPrefixes() {
        Set<String> validPrefixes = Set.of("user", "credential", "vault", "audit", "jwt", "hmac",
                "encryption", "file", "config");
        for (SensitiveDataElement element : SensitiveDataElement.values()) {
            String prefix = element.getFieldPath().split("\\.")[0];
            assertTrue(validPrefixes.contains(prefix),
                    "Unexpected field path prefix '" + prefix + "' in " + element.getFieldPath());
        }
    }
}
