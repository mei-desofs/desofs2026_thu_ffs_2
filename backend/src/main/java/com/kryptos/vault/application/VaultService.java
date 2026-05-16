package com.kryptos.vault.application;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.user.domain.UserRepository;
import com.kryptos.vault.application.dto.CreateVaultRequest;
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

    private final VaultRepository vaultRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    @Transactional
    public VaultResponse create(CreateVaultRequest request, UUID ownerId) {
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
        Vault vault = vaultRepository.findByIdAndOwnerId(id, ownerId)
                .orElseThrow(() -> new ResourceNotFoundException("Vault not found"));
        return toResponse(vault, ownerId);
    }

    @Transactional
    public void delete(UUID id, UUID ownerId) {
        if (!vaultRepository.existsByIdAndOwnerId(id, ownerId)) {
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
