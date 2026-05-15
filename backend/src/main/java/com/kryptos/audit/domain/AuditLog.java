package com.kryptos.audit.domain;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "audit_logs")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false)
    private UUID id;

    @Column(nullable = false, updatable = false)
    private String action;

    @Column(nullable = false, updatable = false)
    private String performedBy;

    @Column(updatable = false)
    private String targetResource;

    @Column(updatable = false, length = 1000)
    private String details;

    @Column(nullable = false, updatable = false)
    private LocalDateTime timestamp;

    @Column(updatable = false, length = 64)
    private String hash;

    @Column(name = "previous_hash", updatable = false, length = 64)
    private String previousHash;

    @PrePersist
    void onPrePersist() {
        if (timestamp == null) {
            timestamp = LocalDateTime.now();
        }
    }

    @PreUpdate
    void onPreUpdate() {
        throw new UnsupportedOperationException("Audit log entries are immutable and cannot be modified");
    }

    @PreRemove
    void onPreRemove() {
        throw new UnsupportedOperationException("Audit log entries are immutable and cannot be deleted");
    }
}
