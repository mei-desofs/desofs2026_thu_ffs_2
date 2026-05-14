package com.kryptos.credential;

import com.kryptos.credential.application.CredentialService;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.shared.encryption.EncryptionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CredentialServiceTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private EncryptionService encryptionService;

    @InjectMocks
    private CredentialService credentialService;

    @Test
    void create_shouldEncryptPassword_beforeSaving() {
        // TODO
    }

    @Test
    void findById_shouldThrow_whenUserDoesNotOwnCredential() {
        // TODO
    }

    @Test
    void findAllByVault_shouldThrow_whenUserDoesNotOwnVault() {
        // TODO
    }
}
