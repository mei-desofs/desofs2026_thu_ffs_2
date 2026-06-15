package com.kryptos.user.domain;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BackupCodeRepository extends JpaRepository<BackupCode, UUID> {
    List<BackupCode> findByUserId(UUID userId);
    List<BackupCode> findByUserIdAndUsedFalse(UUID userId);
}
