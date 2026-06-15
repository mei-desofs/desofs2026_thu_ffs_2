package com.kryptos.shared.dataprotection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class DataClassificationServiceTest {

    private DataClassificationService service;

    @BeforeEach
    void setUp() {
        service = new DataClassificationService();
    }

    @Test
    void classify_shouldReturnConfidential_forEncryptedPassword() {
        assertEquals(DataClassification.CONFIDENTIAL, service.classify("credential.encryptedPassword"));
    }

    @Test
    void classify_shouldReturnRestricted_forEncryptionSecret() {
        assertEquals(DataClassification.RESTRICTED, service.classify("encryption.secret"));
    }

    @Test
    void classify_shouldReturnInternal_forUsername() {
        assertEquals(DataClassification.INTERNAL, service.classify("user.username"));
    }

    @Test
    void classify_shouldReturnPublic_forServiceName() {
        assertEquals(DataClassification.PUBLIC, service.classify("credential.serviceName"));
    }

    @Test
    void classify_shouldThrow_forUnknownFieldPath() {
        assertThrows(IllegalArgumentException.class, () -> service.classify("unknown.field"));
    }

    @Test
    void getElement_shouldReturnCorrectElement() {
        SensitiveDataElement element = service.getElement("user.email");
        assertEquals(SensitiveDataElement.USER_EMAIL, element);
    }

    @Test
    void getElement_shouldThrow_forUnknownPath() {
        assertThrows(IllegalArgumentException.class, () -> service.getElement("does.not.exist"));
    }

    @Test
    void getProtectionRequirements_shouldReturnRequirements_forConfidential() {
        List<DataClassificationService.ProtectionRequirement> reqs =
                service.getProtectionRequirements(DataClassification.CONFIDENTIAL);
        assertNotNull(reqs);
        assertFalse(reqs.isEmpty());
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Encryption at Rest")));
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Encoding Awareness")));
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Logging")));
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Database Encryption")));
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Privacy")));
    }

    @Test
    void getProtectionRequirements_shouldReturnRequirements_forRestricted() {
        List<DataClassificationService.ProtectionRequirement> reqs =
                service.getProtectionRequirements(DataClassification.RESTRICTED);
        assertNotNull(reqs);
        assertFalse(reqs.isEmpty());
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Regulatory Compliance")));
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Logging")));
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Database Encryption")));
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Privacy")));
    }

    @Test
    void getProtectionRequirements_shouldReturnRequirements_forPublic() {
        List<DataClassificationService.ProtectionRequirement> reqs =
                service.getProtectionRequirements(DataClassification.PUBLIC);
        assertNotNull(reqs);
        assertFalse(reqs.isEmpty());
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Logging")));
    }

    @Test
    void getProtectionRequirements_shouldReturnRequirements_forInternal() {
        List<DataClassificationService.ProtectionRequirement> reqs =
                service.getProtectionRequirements(DataClassification.INTERNAL);
        assertNotNull(reqs);
        assertFalse(reqs.isEmpty());
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Logging")));
        assertTrue(reqs.stream().anyMatch(r -> r.category().equals("Privacy")));
    }

    @Test
    void getApplicableRegulations_shouldReturnGDPR_forRestricted() {
        List<String> regs = service.getApplicableRegulations(DataClassification.RESTRICTED);
        assertTrue(regs.stream().anyMatch(r -> r.contains("GDPR")));
    }

    @Test
    void getApplicableRegulations_shouldReturnEmpty_forPublic() {
        List<String> regs = service.getApplicableRegulations(DataClassification.PUBLIC);
        assertTrue(regs.isEmpty());
    }

    @Test
    void getElementsByClassification_shouldReturnAllRestricted() {
        List<SensitiveDataElement> restricted = service.getElementsByClassification(DataClassification.RESTRICTED);
        assertFalse(restricted.isEmpty());
        assertTrue(restricted.contains(SensitiveDataElement.ENCRYPTION_SECRET));
        assertTrue(restricted.contains(SensitiveDataElement.USER_PASSWORD_HASH));
        assertTrue(restricted.contains(SensitiveDataElement.JWT_SIGNING_SECRET));
    }

    @Test
    void getElementsByClassification_shouldReturnAllPublic() {
        List<SensitiveDataElement> publicElements = service.getElementsByClassification(DataClassification.PUBLIC);
        assertFalse(publicElements.isEmpty());
        assertTrue(publicElements.contains(SensitiveDataElement.CREDENTIAL_SERVICE_NAME));
        assertTrue(publicElements.contains(SensitiveDataElement.VAULT_NAME));
    }

    @Test
    void isProperlyProtected_shouldReturnTrue_whenAllRequirementsMet() {
        assertTrue(service.isProperlyProtected(
                SensitiveDataElement.CREDENTIAL_ENCRYPTED_PASSWORD, true, true, true, true, true, true));
    }

    @Test
    void isProperlyProtected_shouldReturnFalse_whenEncryptionAtRestMissing() {
        assertFalse(service.isProperlyProtected(
                SensitiveDataElement.CREDENTIAL_ENCRYPTED_PASSWORD, false, true, true, true, true, true));
    }

    @Test
    void isProperlyProtected_shouldReturnFalse_whenAccessControlMissing() {
        assertFalse(service.isProperlyProtected(
                SensitiveDataElement.ENCRYPTION_SECRET, true, true, false, true, true, true));
    }

    @Test
    void isProperlyProtected_shouldReturnTrue_forPublicEvenWithoutProtection() {
        assertTrue(service.isProperlyProtected(
                SensitiveDataElement.CREDENTIAL_SERVICE_NAME, false, false, false, false, false, false));
    }

    @Test
    void isProperlyProtected_shouldReturnFalse_whenLoggingProtectionMissing() {
        assertFalse(service.isProperlyProtected(
                SensitiveDataElement.ENCRYPTION_SECRET, true, true, true, false, true, true));
    }

    @Test
    void isProperlyProtected_shouldReturnFalse_whenDatabaseEncryptionMissing() {
        assertFalse(service.isProperlyProtected(
                SensitiveDataElement.ENCRYPTION_SECRET, true, true, true, true, false, true));
    }

    @Test
    void isProperlyProtected_shouldReturnFalse_whenPrivacyEnhancementMissing() {
        assertFalse(service.isProperlyProtected(
                SensitiveDataElement.ENCRYPTION_SECRET, true, true, true, true, true, false));
    }

    @Test
    void isEncodedOnly_shouldReturnTrue_forConfidential() {
        assertTrue(service.isEncodedOnly(DataClassification.CONFIDENTIAL));
    }

    @Test
    void isEncodedOnly_shouldReturnFalse_forOtherLevels() {
        assertFalse(service.isEncodedOnly(DataClassification.PUBLIC));
        assertFalse(service.isEncodedOnly(DataClassification.INTERNAL));
        assertFalse(service.isEncodedOnly(DataClassification.RESTRICTED));
    }

    @Test
    void getClassificationForElement_shouldReturnCorrect_whenFound() {
        Optional<DataClassification> result = service.getClassificationForElement("jwt.token");
        assertTrue(result.isPresent());
        assertEquals(DataClassification.CONFIDENTIAL, result.get());
    }

    @Test
    void getClassificationForElement_shouldReturnEmpty_whenNotFound() {
        assertTrue(service.getClassificationForElement("nonexistent.path").isEmpty());
    }

    @Test
    void getAllFieldPaths_shouldContainAllRegisteredElements() {
        var paths = service.getAllFieldPaths();
        assertTrue(paths.contains("user.username"));
        assertTrue(paths.contains("credential.encryptedPassword"));
        assertTrue(paths.contains("encryption.secret"));
        assertTrue(paths.contains("jwt.token"));
        assertTrue(paths.contains("config.databasePassword"));
    }

    @Test
    void countElementsAtLevel_shouldReturnCorrectCounts() {
        long total = SensitiveDataElement.values().length;
        long publicCount = service.countElementsAtLevel(DataClassification.PUBLIC);
        long internalCount = service.countElementsAtLevel(DataClassification.INTERNAL);
        long confidentialCount = service.countElementsAtLevel(DataClassification.CONFIDENTIAL);
        long restrictedCount = service.countElementsAtLevel(DataClassification.RESTRICTED);
        assertEquals(total, publicCount + internalCount + confidentialCount + restrictedCount);
    }

    @Test
    void protectionRequirementRecord_shouldWork() {
        var req = new DataClassificationService.ProtectionRequirement("Test", "Description");
        assertEquals("Test", req.category());
        assertEquals("Description", req.requirement());
    }

    @Test
    void sanitizeForLogging_shouldReturnValueUnchanged_forPublicData() {
        String result = service.sanitizeForLogging("visible data", SensitiveDataElement.CREDENTIAL_SERVICE_NAME);
        assertEquals("visible data", result);
    }

    @Test
    void sanitizeForLogging_shouldReturnValueUnchanged_forInternalData() {
        String result = service.sanitizeForLogging("user@example.com", SensitiveDataElement.USER_EMAIL);
        assertEquals("user@example.com", result);
    }

    @Test
    void sanitizeForLogging_shouldMaskConfidentialData() {
        String result = service.sanitizeForLogging("my-secret-token-123", SensitiveDataElement.JWT_TOKEN);
        assertEquals("my****23", result);
    }

    @Test
    void sanitizeForLogging_shouldMaskShortConfidentialData() {
        String result = service.sanitizeForLogging("abcd", SensitiveDataElement.JWT_TOKEN);
        assertEquals("****", result);
    }

    @Test
    void sanitizeForLogging_shouldRedactRestrictedData() {
        String result = service.sanitizeForLogging("super-secret-key", SensitiveDataElement.ENCRYPTION_SECRET);
        assertEquals("[REDACTED]", result);
    }

    @Test
    void sanitizeForLogging_shouldHandleNullValue() {
        String result = service.sanitizeForLogging(null, SensitiveDataElement.ENCRYPTION_SECRET);
        assertNull(result);
    }

    @Test
    void getLoggingProtection_shouldReturnClassification() {
        assertEquals(DataClassification.CONFIDENTIAL,
                service.getLoggingProtection(DataClassification.CONFIDENTIAL));
        assertEquals(DataClassification.RESTRICTED,
                service.getLoggingProtection(DataClassification.RESTRICTED));
        assertEquals(DataClassification.PUBLIC,
                service.getLoggingProtection(DataClassification.PUBLIC));
    }
}
