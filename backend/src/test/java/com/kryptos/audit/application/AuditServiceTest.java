package com.kryptos.audit.application;

import com.kryptos.audit.domain.AuditLog;
import com.kryptos.audit.domain.AuditLogRepository;
import com.kryptos.shared.dataprotection.DataClassificationService;
import com.kryptos.shared.dataprotection.SensitiveDataElement;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private LogForwardingService logForwardingService;

    @Mock
    private DataClassificationService dataClassificationService;

    @InjectMocks
    private AuditService auditService;

    @Test
    void log_shouldPersistEntryWithCorrectFields() {
        when(auditLogRepository.findFirstByOrderByTimestampDesc()).thenReturn(Optional.empty());

        auditService.log("LOGIN", "user1", "auth", "Successful login");

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog saved = captor.getValue();
        assertEquals("LOGIN", saved.getAction());
        assertEquals("user1", saved.getPerformedBy());
        assertEquals("auth", saved.getTargetResource());
        assertEquals("Successful login", saved.getDetails());
        assertNotNull(saved.getTimestamp());
        assertNotNull(saved.getHash());
        assertNull(saved.getPreviousHash());
    }

    @Test
    void log_shouldBuildHashChain() {
        AuditLog previous = AuditLog.builder()
                .action("LOGIN")
                .performedBy("user1")
                .targetResource("auth")
                .details("First login")
                .timestamp(java.time.LocalDateTime.now().minusMinutes(5))
                .hash("abc123")
                .build();

        when(auditLogRepository.findFirstByOrderByTimestampDesc()).thenReturn(Optional.of(previous));

        auditService.log("LOGIN", "user2", "auth", "Second login");

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog saved = captor.getValue();
        assertNotNull(saved.getHash());
        assertEquals("abc123", saved.getPreviousHash());
    }

    @Test
    void log_shouldSanitizeDetails() {
        when(auditLogRepository.findFirstByOrderByTimestampDesc()).thenReturn(Optional.empty());

        auditService.log("LOGIN", "user1", "auth", "Details with\nnewline\r\nand\0null chars");

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog saved = captor.getValue();
        assertFalse(saved.getDetails().contains("\n"));
        assertFalse(saved.getDetails().contains("\r"));
        assertFalse(saved.getDetails().contains("\0"));
    }

    @Test
    void log_shouldHandleNullDetails() {
        when(auditLogRepository.findFirstByOrderByTimestampDesc()).thenReturn(Optional.empty());

        auditService.log("LOGIN", "user1", "auth", null);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        assertNull(captor.getValue().getDetails());
    }

    @Test
    void log_shouldHandleEmptyDetails() {
        when(auditLogRepository.findFirstByOrderByTimestampDesc()).thenReturn(Optional.empty());

        auditService.log("LOGIN", "user1", "auth", "");

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        assertEquals("", captor.getValue().getDetails());
    }

    @Test
    void logSensitive_shouldSanitizeConfidentialData() {
        when(auditLogRepository.findFirstByOrderByTimestampDesc()).thenReturn(Optional.empty());
        when(dataClassificationService.sanitizeForLogging("plaintext-token-123", SensitiveDataElement.JWT_TOKEN))
                .thenReturn("pl****23");

        auditService.logSensitive("LOGIN", "user1", "auth",
                "plaintext-token-123", SensitiveDataElement.JWT_TOKEN);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog saved = captor.getValue();
        assertEquals("pl****23", saved.getDetails());
        assertEquals("LOGIN", saved.getAction());
        assertEquals("user1", saved.getPerformedBy());
    }

    @Test
    void logSensitive_shouldRedactRestrictedData() {
        when(auditLogRepository.findFirstByOrderByTimestampDesc()).thenReturn(Optional.empty());
        when(dataClassificationService.sanitizeForLogging("super-secret-key", SensitiveDataElement.ENCRYPTION_SECRET))
                .thenReturn("[REDACTED]");

        auditService.logSensitive("CONFIG_CHANGE", "admin", "encryption",
                "super-secret-key", SensitiveDataElement.ENCRYPTION_SECRET);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog saved = captor.getValue();
        assertEquals("[REDACTED]", saved.getDetails());
    }
}
