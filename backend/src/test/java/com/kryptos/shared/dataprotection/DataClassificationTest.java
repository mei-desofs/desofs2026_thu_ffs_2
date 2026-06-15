package com.kryptos.shared.dataprotection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DataClassificationTest {

    @Test
    void shouldHaveFourLevels() {
        assertEquals(4, DataClassification.values().length);
    }

    @Test
    void levelsShouldBeInCorrectOrdinalOrder() {
        assertTrue(DataClassification.PUBLIC.ordinal() < DataClassification.INTERNAL.ordinal());
        assertTrue(DataClassification.INTERNAL.ordinal() < DataClassification.CONFIDENTIAL.ordinal());
        assertTrue(DataClassification.CONFIDENTIAL.ordinal() < DataClassification.RESTRICTED.ordinal());
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
}
