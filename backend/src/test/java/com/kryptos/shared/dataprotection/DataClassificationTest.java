package com.kryptos.shared.dataprotection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DataClassificationTest {

    @Test
    void shouldHaveFourLevels() {
        assertEquals(4, DataClassification.values().length);
    }

    @Test
    void publicLevelShouldNotRequireProtection() {
        assertFalse(DataClassification.PUBLIC.isRequiresEncryptionAtRest());
        assertFalse(DataClassification.PUBLIC.isRequiresEncryptionInTransit());
        assertFalse(DataClassification.PUBLIC.isRequiresStrictAccessControl());
    }

    @Test
    void internalLevelShouldNotRequireEncryptionAtRest() {
        assertFalse(DataClassification.INTERNAL.isRequiresEncryptionAtRest());
        assertTrue(DataClassification.INTERNAL.isRequiresEncryptionInTransit());
        assertTrue(DataClassification.INTERNAL.isRequiresStrictAccessControl());
    }

    @Test
    void confidentialLevelShouldRequireFullProtection() {
        assertTrue(DataClassification.CONFIDENTIAL.isRequiresEncryptionAtRest());
        assertTrue(DataClassification.CONFIDENTIAL.isRequiresEncryptionInTransit());
        assertTrue(DataClassification.CONFIDENTIAL.isRequiresStrictAccessControl());
    }

    @Test
    void restrictedLevelShouldRequireFullProtection() {
        assertTrue(DataClassification.RESTRICTED.isRequiresEncryptionAtRest());
        assertTrue(DataClassification.RESTRICTED.isRequiresEncryptionInTransit());
        assertTrue(DataClassification.RESTRICTED.isRequiresStrictAccessControl());
    }

    @Test
    void displayNamesShouldNotBeBlank() {
        for (DataClassification level : DataClassification.values()) {
            assertNotNull(level.getDisplayName());
            assertFalse(level.getDisplayName().isBlank());
        }
    }

    @Test
    void descriptionsShouldNotBeBlank() {
        for (DataClassification level : DataClassification.values()) {
            assertNotNull(level.getDescription());
            assertFalse(level.getDescription().isBlank());
        }
    }

    @Test
    void retentionGuidanceShouldNotBeBlank() {
        for (DataClassification level : DataClassification.values()) {
            assertNotNull(level.getRetentionGuidance());
            assertFalse(level.getRetentionGuidance().isBlank());
        }
    }

    @Test
    void confidentialDescriptionShouldMentionBase64AndJwt() {
        String desc = DataClassification.CONFIDENTIAL.getDescription();
        assertTrue(desc.contains("Base64"), "CONFIDENTIAL description should mention Base64 encoding risk");
        assertTrue(desc.contains("JWT"), "CONFIDENTIAL description should mention JWT plaintext payload risk");
    }

    @Test
    void isAtLeastShouldWorkCorrectly() {
        assertTrue(DataClassification.PUBLIC.isAtLeast(DataClassification.PUBLIC));
        assertTrue(DataClassification.INTERNAL.isAtLeast(DataClassification.PUBLIC));
        assertTrue(DataClassification.CONFIDENTIAL.isAtLeast(DataClassification.INTERNAL));
        assertTrue(DataClassification.RESTRICTED.isAtLeast(DataClassification.RESTRICTED));
        assertFalse(DataClassification.INTERNAL.isAtLeast(DataClassification.CONFIDENTIAL));
        assertFalse(DataClassification.PUBLIC.isAtLeast(DataClassification.RESTRICTED));
    }

    @Test
    void publicLevelShouldNotRequireLoggingProtection() {
        assertFalse(DataClassification.PUBLIC.isRequiresLoggingProtection());
    }

    @Test
    void internalLevelShouldRequireLoggingProtection() {
        assertTrue(DataClassification.INTERNAL.isRequiresLoggingProtection());
    }

    @Test
    void confidentialLevelShouldRequireLoggingProtection() {
        assertTrue(DataClassification.CONFIDENTIAL.isRequiresLoggingProtection());
    }

    @Test
    void restrictedLevelShouldRequireLoggingProtection() {
        assertTrue(DataClassification.RESTRICTED.isRequiresLoggingProtection());
    }

    @Test
    void publicAndInternalShouldNotRequireDatabaseEncryption() {
        assertFalse(DataClassification.PUBLIC.isRequiresDatabaseEncryption());
        assertFalse(DataClassification.INTERNAL.isRequiresDatabaseEncryption());
    }

    @Test
    void confidentialAndRestrictedShouldRequireDatabaseEncryption() {
        assertTrue(DataClassification.CONFIDENTIAL.isRequiresDatabaseEncryption());
        assertTrue(DataClassification.RESTRICTED.isRequiresDatabaseEncryption());
    }

    @Test
    void publicLevelShouldNotRequirePrivacyEnhancement() {
        assertFalse(DataClassification.PUBLIC.isRequiresPrivacyEnhancement());
    }

    @Test
    void internalConfidentialRestrictedShouldRequirePrivacyEnhancement() {
        assertTrue(DataClassification.INTERNAL.isRequiresPrivacyEnhancement());
        assertTrue(DataClassification.CONFIDENTIAL.isRequiresPrivacyEnhancement());
        assertTrue(DataClassification.RESTRICTED.isRequiresPrivacyEnhancement());
    }

    @Test
    void loggingGuidanceShouldNotBeBlank() {
        for (DataClassification level : DataClassification.values()) {
            assertNotNull(level.getLoggingGuidance());
            assertFalse(level.getLoggingGuidance().isBlank());
        }
    }

    @Test
    void publicLoggingGuidanceShouldAllowFreeLogging() {
        assertTrue(DataClassification.PUBLIC.getLoggingGuidance().contains("No logging restrictions"));
    }

    @Test
    void confidentialLoggingGuidanceShouldRequireMasking() {
        assertTrue(DataClassification.CONFIDENTIAL.getLoggingGuidance().contains("masked or redacted"));
    }

    @Test
    void restrictedLoggingGuidanceShouldProhibitLogging() {
        assertTrue(DataClassification.RESTRICTED.getLoggingGuidance().contains("never appear in logs"));
    }
}
