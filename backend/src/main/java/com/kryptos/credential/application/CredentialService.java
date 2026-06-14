package com.kryptos.credential.application;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.credential.application.dto.CreateCredentialRequest;
import com.kryptos.credential.application.dto.CredentialResponse;
import com.kryptos.credential.domain.Credential;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.shared.encryption.EncryptionService;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.vault.domain.VaultRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CredentialService {

    private final CredentialRepository credentialRepository;
    private final VaultRepository vaultRepository;
    private final EncryptionService encryptionService;
    private final AuditService auditService;

    @Transactional
    public CredentialResponse create(CreateCredentialRequest request, UUID ownerId) {
        if (!vaultRepository.existsByIdAndOwnerId(request.vaultId(), ownerId)) {
            auditService.log(AuditAction.ACCESS_DENIED_CREDENTIAL, currentUsername(),
                    "vault:" + request.vaultId(),
                    "DENIED create credential: vault not found or not owned");
            throw new ForbiddenException("Vault not found or access denied");
        }

        Credential credential = Credential.builder()
                .serviceName(request.serviceName())
                .username(request.username())
                .encryptedPassword(encryptionService.encrypt(request.password()))
                .url(request.url())
                .notes(request.notes())
                .vault(vaultRepository.getReferenceById(request.vaultId()))
                .build();
        credentialRepository.save(credential);

        auditService.log(AuditAction.CREDENTIAL_CREATE, currentUsername(),
                "credential:" + credential.getId(),
                "Created credential for service: " + request.serviceName());

        return toResponse(credential);
    }

    public List<CredentialResponse> findAllByVault(UUID vaultId, UUID ownerId) {
        if (!vaultRepository.existsByIdAndOwnerId(vaultId, ownerId)) {
            auditService.log(AuditAction.ACCESS_DENIED_CREDENTIAL, currentUsername(),
                    "vault:" + vaultId,
                    "DENIED list credentials: vault not found or not owned");
            throw new ForbiddenException("Vault not found or access denied");
        }
        return credentialRepository.findAllByVaultIdAndVaultOwnerId(vaultId, ownerId)
                .stream()
                .map(this::toResponse)
                .toList();
    }

    public CredentialResponse findById(UUID id, UUID ownerId) {
        Credential credential = credentialRepository.findByIdAndVaultOwnerId(id, ownerId).orElse(null);
        if (credential == null) {
            auditService.log(AuditAction.ACCESS_DENIED_CREDENTIAL, currentUsername(),
                    "credential:" + id,
                    "DENIED read: credential not found or not owned");
            throw new ResourceNotFoundException("Credential not found");
        }
        return toResponse(credential);
    }

    @Transactional
    public void delete(UUID id, UUID ownerId) {
        if (!credentialRepository.existsByIdAndVaultOwnerId(id, ownerId)) {
            auditService.log(AuditAction.ACCESS_DENIED_CREDENTIAL, currentUsername(),
                    "credential:" + id,
                    "DENIED delete: credential not found or not owned");
            throw new ForbiddenException("Credential not found or access denied");
        }
        credentialRepository.deleteById(id);

        auditService.log(AuditAction.CREDENTIAL_DELETE, currentUsername(),
                "credential:" + id, "Deleted credential: " + id);
    }

    private CredentialResponse toResponse(Credential credential) {
        return new CredentialResponse(
                credential.getId(),
                credential.getServiceName(),
                credential.getUsername(),
                credential.getUrl(),
                credential.getNotes(),
                credential.getVault().getId()
        );
    }

    private String currentUsername() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
