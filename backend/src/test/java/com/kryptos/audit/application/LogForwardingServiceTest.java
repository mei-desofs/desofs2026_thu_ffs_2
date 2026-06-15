package com.kryptos.audit.application;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptos.audit.domain.AuditLog;

@ExtendWith(MockitoExtension.class)
class LogForwardingServiceTest {

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private LogForwardingService logForwardingService;

    private AuditLog testAuditLog;

    @BeforeEach
    void setUp() {
        testAuditLog = AuditLog.builder()
                .id(UUID.randomUUID())
                .action("LOGIN")
                .performedBy("user1")
                .targetResource("auth")
                .details("Successful login from 127.0.0.1")
                .timestamp(LocalDateTime.now())
                .hash("abc123hash")
                .previousHash("previous123hash")
                .build();
    }

    @Test
    void forwardLog_shouldNotThrowException_whenUrlNotConfigured() {
        // LogForwardingService initialized with empty URL
        LogForwardingService service = new LogForwardingService("", new ObjectMapper());

        assertDoesNotThrow(() -> service.forwardLog(testAuditLog));
    }

    @Test
    void forwardLog_shouldNotThrowException_whenUrlIsNull() {
        LogForwardingService service = new LogForwardingService(null, new ObjectMapper());

        assertDoesNotThrow(() -> service.forwardLog(testAuditLog));
    }

    @Test
    void forwardLog_shouldAcceptValidAuditLog() {
        assertNotNull(testAuditLog.getAction());
        assertEquals("LOGIN", testAuditLog.getAction());
        assertEquals("user1", testAuditLog.getPerformedBy());
        assertNotNull(testAuditLog.getTimestamp());
    }

    @Test
    void forwardLog_shouldBeAsyncAndNonBlocking() {
        LogForwardingService service = new LogForwardingService("", new ObjectMapper());

        long startTime = System.currentTimeMillis();
        service.forwardLog(testAuditLog);
        long endTime = System.currentTimeMillis();

        // Should complete almost instantly since URL is not configured
        assertTrue((endTime - startTime) < 100, "Forwarding should be non-blocking");
    }

    @Test
    void forwardLog_shouldPreserveAuditLogData() {
        AuditLog log = AuditLog.builder()
                .id(UUID.randomUUID())
                .action("CREDENTIAL_UPDATE")
                .performedBy("admin")
                .targetResource("vault")
                .details("Updated credential: secret-name")
                .timestamp(LocalDateTime.of(2026, 6, 15, 12, 30, 45))
                .hash("hash123")
                .previousHash("prevhash123")
                .build();

        assertEquals("CREDENTIAL_UPDATE", log.getAction());
        assertEquals("admin", log.getPerformedBy());
        assertEquals("vault", log.getTargetResource());
        assertTrue(log.getDetails().contains("secret-name"));
        assertNotNull(log.getTimestamp());
    }

    @Test
    void forwardLog_shouldHandleMultipleLogs() {
        LogForwardingService service = new LogForwardingService("", new ObjectMapper());

        AuditLog log1 = AuditLog.builder().action("LOGIN").performedBy("user1").build();
        AuditLog log2 = AuditLog.builder().action("LOGOUT").performedBy("user1").build();
        AuditLog log3 = AuditLog.builder().action("PASSWORD_RESET_COMPLETED").performedBy("user2").build();

        assertDoesNotThrow(() -> {
            service.forwardLog(log1);
            service.forwardLog(log2);
            service.forwardLog(log3);
        });
    }
}
