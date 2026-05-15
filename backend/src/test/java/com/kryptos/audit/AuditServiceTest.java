package com.kryptos.audit;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditLog;
import com.kryptos.audit.domain.AuditLogRepository;
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
}
