package com.kryptos.audit.application;

import com.kryptos.audit.domain.AuditLog;
import com.kryptos.audit.domain.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public void log(String action, String performedBy, String targetResource, String details) {
        AuditLog entry = AuditLog.builder()
                .action(action)
                .performedBy(performedBy)
                .targetResource(targetResource)
                .details(details)
                .timestamp(LocalDateTime.now())
                .build();
        auditLogRepository.save(entry);
    }
}
