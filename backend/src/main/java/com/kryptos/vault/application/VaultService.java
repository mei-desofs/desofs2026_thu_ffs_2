package com.kryptos.vault.application;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.user.domain.UserRepository;
import com.kryptos.vault.application.dto.CreateVaultRequest;
import com.kryptos.vault.application.dto.UpdateVaultRequest;
import com.kryptos.vault.application.dto.VaultResponse;
import com.kryptos.vault.domain.Vault;
import com.kryptos.vault.domain.VaultRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VaultService {

    private static final int MAX_VAULTS_PER_USER = 50;

    private final VaultRepository vaultRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    @Transactional
    public VaultResponse create(CreateVaultRequest request, UUID ownerId) {
        long currentCount = vaultRepository.countByOwnerId(ownerId);
        if (currentCount >= MAX_VAULTS_PER_USER) {
            throw new IllegalArgumentException(
                    String.format("Maximum number of vaults (%d) reached", MAX_VAULTS_PER_USER));
        }

        Vault vault = Vault.builder()
                .name(request.name())
                .description(request.description())
                .owner(userRepository.getReferenceById(ownerId))
                .build();
        vaultRepository.save(vault);

        auditService.log(AuditAction.VAULT_CREATE, currentUsername(), "vault:" + vault.getId(),
                "Created vault: " + request.name());

        return toResponse(vault, ownerId);
    }

    public List<VaultResponse> findAllByOwner(UUID ownerId) {
        return vaultRepository.findAllByOwnerId(ownerId)
                .stream()
                .map(v -> toResponse(v, ownerId))
                .toList();
    }

    public VaultResponse findById(UUID id, UUID ownerId) {
        Vault vault = vaultRepository.findByIdAndOwnerId(id, ownerId).orElse(null);
        if (vault == null) {
            auditService.log(AuditAction.ACCESS_DENIED_VAULT, currentUsername(), "vault:" + id,
                    "DENIED read: vault not found or not owned");
            throw new ResourceNotFoundException("Vault not found");
        }
        return toResponse(vault, ownerId);
    }

    @Transactional
    public VaultResponse update(UUID vaultId, UpdateVaultRequest request, UUID ownerId) {
        Vault vault = vaultRepository.findByIdAndOwnerId(vaultId, ownerId).orElse(null);
        if (vault == null) {
            auditService.log(AuditAction.ACCESS_DENIED_VAULT, currentUsername(), "vault:" + vaultId,
                    "DENIED update: vault not found or not owned");
            throw new ForbiddenException("Vault not found or access denied");
        }

        vault.setName(request.name());
        vault.setDescription(request.description());
        vaultRepository.save(vault);

        auditService.log(AuditAction.VAULT_UPDATE, currentUsername(), "vault:" + vaultId,
                "Updated vault: " + request.name());

        return toResponse(vault, ownerId);
    }

    @Transactional
    public void delete(UUID id, UUID ownerId) {
        if (!vaultRepository.existsByIdAndOwnerId(id, ownerId)) {
            auditService.log(AuditAction.ACCESS_DENIED_VAULT, currentUsername(), "vault:" + id,
                    "DENIED delete: vault not found or not owned");
            throw new ForbiddenException("Vault not found or access denied");
        }
        vaultRepository.deleteById(id);

        auditService.log(AuditAction.VAULT_DELETE, currentUsername(), "vault:" + id,
                "Deleted vault: " + id);
    }

    private VaultResponse toResponse(Vault vault, UUID ownerId) {
        return new VaultResponse(vault.getId(), vault.getName(), vault.getDescription(), ownerId);
    }

    private String currentUsername() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
