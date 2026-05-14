package com.kryptos.audit.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
    Page<AuditLog> findAllByPerformedBy(String username, Pageable pageable);
    Page<AuditLog> findAll(Pageable pageable);
}
