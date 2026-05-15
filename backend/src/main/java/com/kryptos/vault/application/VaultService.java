package com.kryptos.vault.application;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.vault.application.dto.CreateVaultRequest;
import com.kryptos.vault.application.dto.VaultResponse;
import com.kryptos.vault.domain.VaultRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class VaultService {

    private final VaultRepository vaultRepository;
    private final AuditService auditService;

    public VaultResponse create(CreateVaultRequest request, UUID ownerId) {
        // TODO
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.VAULT_CREATE, username, "vault",
                "Created vault: " + request.name());
        return null;
    }

    public List<VaultResponse> findAllByOwner(UUID ownerId) {
        // TODO
        return List.of();
    }

    public VaultResponse findById(UUID id, UUID ownerId) {
        // TODO
        return null;
    }

    public void delete(UUID id, UUID ownerId) {
        // TODO
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.VAULT_DELETE, username, "vault",
                "Deleted vault: " + id);
    }
}
