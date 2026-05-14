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
        auditService.log("LOGIN", "user1", "auth", "Successful login");

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog saved = captor.getValue();
        assertEquals("LOGIN", saved.getAction());
        assertEquals("user1", saved.getPerformedBy());
        assertNotNull(saved.getTimestamp());
    }
}
