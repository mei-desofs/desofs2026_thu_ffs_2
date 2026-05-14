package com.kryptos.vault.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface VaultRepository extends JpaRepository<Vault, UUID> {
    List<Vault> findAllByOwnerId(UUID ownerId);
    boolean existsByIdAndOwnerId(UUID id, UUID ownerId);
}
