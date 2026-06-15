package com.kryptos.vault.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface VaultRepository extends JpaRepository<Vault, UUID> {
    List<Vault> findAllByOwnerId(UUID ownerId);
    Optional<Vault> findByIdAndOwnerId(UUID id, UUID ownerId);
    boolean existsByIdAndOwnerId(UUID id, UUID ownerId);
    Optional<Vault> findByOwnerIdAndName(UUID ownerId, String name);
    long countByOwnerId(UUID ownerId);
}
