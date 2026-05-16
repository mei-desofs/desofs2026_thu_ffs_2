package com.kryptos.audit.domain;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AuditLogTest {

    @Test
    void onPreUpdate_shouldThrowUnsupportedOperationException() {
        AuditLog auditLog = AuditLog.builder()
                .action("LOGIN")
                .performedBy("user1")
                .targetResource("auth")
                .details("test")
                .build();
        assertThrows(UnsupportedOperationException.class, auditLog::onPreUpdate);
    }

    @Test
    void onPreRemove_shouldThrowUnsupportedOperationException() {
        AuditLog auditLog = AuditLog.builder()
                .action("LOGIN")
                .performedBy("user1")
                .targetResource("auth")
                .details("test")
                .build();
        assertThrows(UnsupportedOperationException.class, auditLog::onPreRemove);
    }

    @Test
    void onPrePersist_shouldSetTimestamp_whenTimestampIsNull() {
        AuditLog auditLog = AuditLog.builder()
                .action("LOGIN")
                .performedBy("user1")
                .targetResource("auth")
                .details("test")
                .build();
        auditLog.onPrePersist();
        assertNotNull(auditLog.getTimestamp());
    }

    @Test
    void onPrePersist_shouldNotOverrideTimestamp() {
        java.time.LocalDateTime ts = java.time.LocalDateTime.of(2026, 5, 16, 0, 0);
        AuditLog auditLog = AuditLog.builder()
                .action("LOGIN")
                .performedBy("user1")
                .targetResource("auth")
                .details("test")
                .timestamp(ts)
                .build();
        auditLog.onPrePersist();
        org.junit.jupiter.api.Assertions.assertEquals(ts, auditLog.getTimestamp());
    }
}
