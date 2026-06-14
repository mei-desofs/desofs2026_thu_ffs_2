package com.kryptos.audit.api;

import com.kryptos.audit.domain.AuditLog;
import com.kryptos.audit.domain.AuditLogRepository;
import com.kryptos.audit.domain.AuditAction;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditLogRepository auditLogRepository;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
    public ResponseEntity<Page<AuditLog>> findAll(Pageable pageable) {
        return ResponseEntity.ok(auditLogRepository.findAll(pageable));
    }

    @GetMapping("/action/{action}")
    @PreAuthorize("hasAnyRole('ADMIN', 'AUDITOR')")
    public ResponseEntity<Page<AuditLog>> findByAction(@PathVariable String action, Pageable pageable) {
        return ResponseEntity.ok(auditLogRepository.findAllByAction(action, pageable));
    }

    @GetMapping("/my-login-history")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<Page<AuditLog>> getMyLoginHistory(Authentication authentication, Pageable pageable) {
        String currentUsername = authentication.getName();
        List<String> loginActions = Arrays.asList(
                AuditAction.LOGIN,
                AuditAction.LOGIN_FAILED,
                AuditAction.PASSWORD_RESET_REQUESTED,
                AuditAction.PASSWORD_RESET_COMPLETED
        );
        return ResponseEntity.ok(
                auditLogRepository.findByPerformedByAndActionInOrderByTimestampDesc(currentUsername, loginActions, pageable)
        );
    }
}
