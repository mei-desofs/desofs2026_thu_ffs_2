package com.kryptos.credential.application;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.credential.application.dto.CreateCredentialRequest;
import com.kryptos.credential.application.dto.CredentialResponse;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.shared.encryption.EncryptionService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CredentialService {

    private final CredentialRepository credentialRepository;
    private final EncryptionService encryptionService;
    private final AuditService auditService;

    public CredentialResponse create(CreateCredentialRequest request, UUID ownerId) {
        // TODO: encrypt password before saving
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.CREDENTIAL_CREATE, username, "credential",
                "Created credential for service: " + request.serviceName());
        return null;
    }

    public List<CredentialResponse> findAllByVault(UUID vaultId, UUID ownerId) {
        // TODO: verify vault ownership before listing
        return List.of();
    }

    public CredentialResponse findById(UUID id, UUID ownerId) {
        // TODO: verify ownership
        return null;
    }

    public void delete(UUID id, UUID ownerId) {
        // TODO: verify ownership
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.CREDENTIAL_DELETE, username, "credential",
                "Deleted credential: " + id);
    }
}
