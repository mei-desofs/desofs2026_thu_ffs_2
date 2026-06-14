package com.kryptos.audit.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
    Page<AuditLog> findAllByAction(String action, Pageable pageable);
    Page<AuditLog> findAll(Pageable pageable);
    Optional<AuditLog> findFirstByOrderByTimestampDesc();
    Page<AuditLog> findByPerformedByAndActionInOrderByTimestampDesc(String performedBy, List<String> actions, Pageable pageable);
}
