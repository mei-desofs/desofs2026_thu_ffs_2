package com.kryptos.credential.application;

import com.kryptos.credential.domain.Credential;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.shared.encryption.EncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CryptoMigrationServiceTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private EncryptionService encryptionService;

    @InjectMocks
    private CryptoMigrationService cryptoMigrationService;

    private Credential credential1;
    private Credential credential2;

    @BeforeEach
    void setUp() {
        credential1 = new Credential();
        credential1.setId(UUID.randomUUID());
        credential1.setEncryptedPassword("old_encrypted_1");

        credential2 = new Credential();
        credential2.setId(UUID.randomUUID());
        credential2.setEncryptedPassword("old_encrypted_2");
    }

    @Test
    void migrateAllCredentials_shouldDecryptAndReencryptAllRecords() {
        when(credentialRepository.findAll()).thenReturn(List.of(credential1, credential2));
        
        when(encryptionService.decrypt("old_encrypted_1")).thenReturn("plain_1");
        when(encryptionService.encrypt("plain_1")).thenReturn("v2$new_encrypted_1");

        when(encryptionService.decrypt("old_encrypted_2")).thenReturn("plain_2");
        when(encryptionService.encrypt("plain_2")).thenReturn("v2$new_encrypted_2");

        int count = cryptoMigrationService.migrateAllCredentials();

        assertEquals(2, count);
        assertEquals("v2$new_encrypted_1", credential1.getEncryptedPassword());
        assertEquals("v2$new_encrypted_2", credential2.getEncryptedPassword());

        verify(credentialRepository).saveAll(List.of(credential1, credential2));
    }

    @Test
    void migrateAllCredentials_shouldSkipEmptyPasswords() {
        Credential emptyCred = new Credential();
        emptyCred.setId(UUID.randomUUID());
        emptyCred.setEncryptedPassword("");

        Credential nullCred = new Credential();
        nullCred.setId(UUID.randomUUID());
        nullCred.setEncryptedPassword(null);

        when(credentialRepository.findAll()).thenReturn(List.of(emptyCred, nullCred));

        int count = cryptoMigrationService.migrateAllCredentials();

        assertEquals(0, count);
        verify(encryptionService, never()).decrypt(anyString());
        verify(encryptionService, never()).encrypt(anyString());
        verify(credentialRepository).saveAll(any());
    }

    @Test
    void migrateAllCredentials_shouldContinueOnDecryptionFailure() {
        when(credentialRepository.findAll()).thenReturn(List.of(credential1, credential2));
        
        // Simulating a failure on the first credential
        when(encryptionService.decrypt("old_encrypted_1")).thenThrow(new RuntimeException("Decryption failed"));
        
        // Second credential succeeds
        when(encryptionService.decrypt("old_encrypted_2")).thenReturn("plain_2");
        when(encryptionService.encrypt("plain_2")).thenReturn("v2$new_encrypted_2");

        int count = cryptoMigrationService.migrateAllCredentials();

        assertEquals(1, count); // Only one successful migration
        assertEquals("old_encrypted_1", credential1.getEncryptedPassword()); // Should not have changed
        assertEquals("v2$new_encrypted_2", credential2.getEncryptedPassword());

        verify(credentialRepository).saveAll(List.of(credential1, credential2));
    }
}
