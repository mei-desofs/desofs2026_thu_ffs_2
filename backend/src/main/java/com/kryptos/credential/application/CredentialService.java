package com.kryptos.credential.application;

import com.kryptos.credential.application.dto.CreateCredentialRequest;
import com.kryptos.credential.application.dto.CredentialResponse;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.shared.encryption.EncryptionService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CredentialService {

    private final CredentialRepository credentialRepository;
    private final EncryptionService encryptionService;

    public CredentialResponse create(CreateCredentialRequest request, UUID ownerId) {
        // TODO: encrypt password before saving
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
    }
}
