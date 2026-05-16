package com.kryptos.filehandling;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptos.credential.domain.Credential;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.filehandling.application.CredentialImportExportService;
import com.kryptos.filehandling.application.FileHandlingService;
import com.kryptos.filehandling.application.dto.CredentialExportRecord;
import com.kryptos.shared.encryption.EncryptionService;
import com.kryptos.shared.exception.EncryptionException;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;
import com.kryptos.vault.domain.Vault;
import com.kryptos.vault.domain.VaultRepository;
import com.kryptos.shared.exception.ResourceNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialImportExportServiceTest {

    @Mock private CredentialRepository credentialRepository;
    @Mock private VaultRepository vaultRepository;
    @Mock private UserRepository userRepository;
    @Mock private EncryptionService encryptionService;
    @Mock private FileHandlingService fileHandlingService;

    @InjectMocks
    private CredentialImportExportService service;

    private UUID ownerId;
    private User owner;
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        ownerId = UUID.randomUUID();
        owner = User.builder().id(ownerId).username("alice").build();
    }

    @Test
    void importForOwner_shouldRejectEmptyBytes() {
        assertThrows(IllegalArgumentException.class,
                () -> service.importForOwner(new byte[0], "x.kvault", ownerId));
        verifyNoInteractions(userRepository, fileHandlingService);
    }

    @Test
    void importForOwner_shouldSkipMalformedLines_andCountOnlyValidRecords() throws Exception {
        when(userRepository.findById(ownerId)).thenReturn(Optional.of(owner));
        Path stored = Paths.get("/tmp/kryptos/import-xyz.kvault");
        when(fileHandlingService.storeUpload(any(), anyString())).thenReturn(stored);
        when(fileHandlingService.importCredentials(stored))
                .thenReturn(List.of("VALID_CT", "GARBAGE_CT"));

        CredentialExportRecord valid = new CredentialExportRecord(
                "github.com", "alice-dev", "p4ss!", "https://github.com", null, "Personal");
        when(encryptionService.decrypt("VALID_CT")).thenReturn(mapper.writeValueAsString(valid));
        when(encryptionService.decrypt("GARBAGE_CT"))
                .thenThrow(new EncryptionException("bad cipher", new RuntimeException()));
        when(encryptionService.encrypt("p4ss!")).thenReturn("RE_ENC");
        when(vaultRepository.findByOwnerIdAndName(ownerId, "Personal"))
                .thenReturn(Optional.of(Vault.builder().id(UUID.randomUUID())
                        .name("Personal").owner(owner).build()));

        int imported = service.importForOwner("payload".getBytes(), "in.kvault", ownerId);

        assertEquals(1, imported);
        ArgumentCaptor<Credential> saved = ArgumentCaptor.forClass(Credential.class);
        verify(credentialRepository).save(saved.capture());
        assertEquals("github.com", saved.getValue().getServiceName());
        assertEquals("RE_ENC", saved.getValue().getEncryptedPassword());
    }

    @Test
    void importForOwner_shouldAutoCreateVault_whenVaultNameUnknown() throws Exception {
        when(userRepository.findById(ownerId)).thenReturn(Optional.of(owner));
        Path stored = Paths.get("/tmp/kryptos/import-abc.kvault");
        when(fileHandlingService.storeUpload(any(), anyString())).thenReturn(stored);
        when(fileHandlingService.importCredentials(stored)).thenReturn(List.of("CT"));

        CredentialExportRecord record = new CredentialExportRecord(
                "svc", "u", "p", null, null, "BrandNewVault");
        when(encryptionService.decrypt("CT")).thenReturn(mapper.writeValueAsString(record));
        when(encryptionService.encrypt("p")).thenReturn("CT2");
        when(vaultRepository.findByOwnerIdAndName(ownerId, "BrandNewVault"))
                .thenReturn(Optional.empty());
        when(vaultRepository.save(any(Vault.class))).thenAnswer(inv -> inv.getArgument(0));

        service.importForOwner("payload".getBytes(), "in.kvault", ownerId);

        ArgumentCaptor<Vault> created = ArgumentCaptor.forClass(Vault.class);
        verify(vaultRepository).save(created.capture());
        assertEquals("BrandNewVault", created.getValue().getName());
        assertEquals(owner, created.getValue().getOwner());
    }

    @Test
    void exportForOwner_shouldThrowResourceNotFound_whenOwnerDoesNotExist() {
        when(userRepository.findById(ownerId)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> service.exportForOwner(ownerId));
    }

    @Test
    void exportForOwner_throws_whenCalledWithoutExportMethodOverride() {
        assertThrows(ResourceNotFoundException.class,
                () -> service.exportForOwner(UUID.randomUUID()));
    }
}
