package com.kryptos.shared.dataprotection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class DataRetentionServiceTest {

    private DataRetentionService service;

    @BeforeEach
    void setUp() {
        service = new DataRetentionService();
    }

    @Test
    void getRetentionPolicy_shouldReturnNonNull_forAllClassifications() {
        for (DataClassification cls : DataClassification.values()) {
            assertNotNull(service.getRetentionPolicy(cls),
                    "Retention policy should exist for " + cls);
        }
    }

    @Test
    void getRetentionPolicy_shouldReturnPolicyWithExpiry_forInternal() {
        DataRetentionPolicy policy = service.getRetentionPolicy(DataClassification.INTERNAL);
        assertTrue(policy.hasExpiry());
        assertEquals(RetentionAction.REVIEW, policy.actionOnExpiry());
    }

    @Test
    void getRetentionPolicy_shouldReturnPolicyWithExpiry_forConfidential() {
        DataRetentionPolicy policy = service.getRetentionPolicy(DataClassification.CONFIDENTIAL);
        assertTrue(policy.hasExpiry());
        assertEquals(Duration.ofDays(90), policy.retentionDuration());
        assertEquals(RetentionAction.DELETE, policy.actionOnExpiry());
    }

    @Test
    void getRetentionPolicy_shouldReturnPolicyWithExpiry_forRestricted() {
        DataRetentionPolicy policy = service.getRetentionPolicy(DataClassification.RESTRICTED);
        assertTrue(policy.hasExpiry());
        assertEquals(Duration.ofDays(30), policy.retentionDuration());
        assertEquals(RetentionAction.DELETE, policy.actionOnExpiry());
    }

    @Test
    void getRetentionPolicy_shouldReturnPolicyWithoutExpiry_forPublic() {
        DataRetentionPolicy policy = service.getRetentionPolicy(DataClassification.PUBLIC);
        assertFalse(policy.hasExpiry());
        assertNull(policy.retentionDuration());
        assertEquals(RetentionAction.REVIEW, policy.actionOnExpiry());
    }

    @Test
    void isExpired_shouldReturnTrue_whenPastRetentionPeriod() {
        Instant now = Instant.now();
        Instant createdAt = now.minus(Duration.ofDays(400));
        assertTrue(service.isExpired(DataClassification.INTERNAL, createdAt, now));
    }

    @Test
    void isExpired_shouldReturnFalse_whenWithinRetentionPeriod() {
        Instant now = Instant.now();
        Instant createdAt = now.minus(Duration.ofDays(30));
        assertFalse(service.isExpired(DataClassification.CONFIDENTIAL, createdAt, now));
    }

    @Test
    void isExpired_shouldReturnFalse_whenExactlyAtExpiry() {
        Instant createdAt = Instant.parse("2026-01-01T00:00:00Z");
        Instant now = createdAt.plus(Duration.ofDays(90));
        assertFalse(service.isExpired(DataClassification.CONFIDENTIAL, createdAt, now));
    }

    @Test
    void isExpired_shouldReturnFalse_forPublicClassification() {
        Instant now = Instant.now();
        Instant createdAt = now.minus(Duration.ofDays(2000));
        assertFalse(service.isExpired(DataClassification.PUBLIC, createdAt, now));
    }

    @Test
    void isExpired_shouldAcceptSensitiveDataElement() {
        Instant now = Instant.now();
        Instant createdAt = now.minus(Duration.ofDays(60));
        assertTrue(service.isExpired(SensitiveDataElement.ENCRYPTION_SECRET, createdAt, now));
    }

    @Test
    void getExpiryDate_shouldReturnCorrectDate_forConfidential() {
        Instant createdAt = Instant.parse("2026-01-01T00:00:00Z");
        Instant expectedExpiry = createdAt.plus(Duration.ofDays(90));
        assertEquals(expectedExpiry, service.getExpiryDate(DataClassification.CONFIDENTIAL, createdAt));
    }

    @Test
    void getExpiryDate_shouldReturnNull_forPublic() {
        Instant createdAt = Instant.parse("2026-01-01T00:00:00Z");
        assertNull(service.getExpiryDate(DataClassification.PUBLIC, createdAt));
    }

    @Test
    void getExpiryDate_shouldAcceptSensitiveDataElement() {
        Instant createdAt = Instant.parse("2026-01-01T00:00:00Z");
        Instant expectedExpiry = createdAt.plus(Duration.ofDays(30));
        assertEquals(expectedExpiry,
                service.getExpiryDate(SensitiveDataElement.ENCRYPTION_SECRET, createdAt));
    }

    @Test
    void retentionPolicyRecord_shouldWork() {
        var policy = new DataRetentionPolicy(Duration.ofDays(7), RetentionAction.DELETE);
        assertEquals(Duration.ofDays(7), policy.retentionDuration());
        assertEquals(RetentionAction.DELETE, policy.actionOnExpiry());
    }

    @Test
    void hasExpiry_shouldReturnFalse_whenDurationNull() {
        var policy = new DataRetentionPolicy(null, RetentionAction.REVIEW);
        assertFalse(policy.hasExpiry());
    }

    @Test
    void hasExpiry_shouldReturnFalse_whenDurationZero() {
        var policy = new DataRetentionPolicy(Duration.ZERO, RetentionAction.REVIEW);
        assertFalse(policy.hasExpiry());
    }
}
