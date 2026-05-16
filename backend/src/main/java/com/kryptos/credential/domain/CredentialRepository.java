package com.kryptos.credential.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CredentialRepository extends JpaRepository<Credential, UUID> {
    List<Credential> findAllByVaultId(UUID vaultId);
    List<Credential> findAllByVaultIdAndVaultOwnerId(UUID vaultId, UUID ownerId);
    Optional<Credential> findByIdAndVaultOwnerId(UUID id, UUID ownerId);
    boolean existsByIdAndVaultOwnerId(UUID id, UUID ownerId);
}
