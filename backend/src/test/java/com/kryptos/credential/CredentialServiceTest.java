package com.kryptos.credential;

import com.kryptos.audit.application.AuditService;
import com.kryptos.credential.application.CredentialService;
import com.kryptos.credential.application.dto.CreateCredentialRequest;
import com.kryptos.credential.application.dto.CredentialResponse;
import com.kryptos.credential.domain.Credential;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.shared.encryption.EncryptionService;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.user.domain.User;
import com.kryptos.vault.domain.Vault;
import com.kryptos.vault.domain.VaultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialServiceTest {

    @Mock private CredentialRepository credentialRepository;
    @Mock private VaultRepository vaultRepository;
    @Mock private EncryptionService encryptionService;
    @Mock private AuditService auditService;

    @InjectMocks
    private CredentialService credentialService;

    private UUID ownerId;
    private UUID vaultId;
    private User owner;
    private Vault vault;

    @BeforeEach
    void setUp() {
        ownerId = UUID.randomUUID();
        vaultId = UUID.randomUUID();
        owner = User.builder().id(ownerId).username("testuser").build();
        vault = Vault.builder().id(vaultId).name("Test Vault").owner(owner).build();

        Authentication auth = mock(Authentication.class);
        lenient().when(auth.getName()).thenReturn("testuser");
        SecurityContext ctx = mock(SecurityContext.class);
        lenient().when(ctx.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(ctx);
    }

    @Test
    void create_shouldEncryptPasswordAndSave() {
        CreateCredentialRequest request = new CreateCredentialRequest(
                vaultId, "GitHub", "user@email.com", "plainPassword", "https://github.com", null);

        Credential saved = Credential.builder()
                .id(UUID.randomUUID())
                .serviceName("GitHub")
                .username("user@email.com")
                .encryptedPassword("encryptedValue")
                .url("https://github.com")
                .vault(vault)
                .build();

        when(vaultRepository.existsByIdAndOwnerId(vaultId, ownerId)).thenReturn(true);
        when(vaultRepository.getReferenceById(vaultId)).thenReturn(vault);
        when(encryptionService.encrypt("plainPassword")).thenReturn("encryptedValue");
        when(credentialRepository.save(any(Credential.class))).thenReturn(saved);

        CredentialResponse response = credentialService.create(request, ownerId);

        assertNotNull(response);
        assertEquals("GitHub", response.serviceName());
        verify(encryptionService).encrypt("plainPassword");
        verify(credentialRepository).save(any(Credential.class));
    }

    @Test
    void create_shouldThrow_whenVaultDoesNotBelongToOwner() {
        CreateCredentialRequest request = new CreateCredentialRequest(
                vaultId, "GitHub", "user", "pass", null, null);

        when(vaultRepository.existsByIdAndOwnerId(vaultId, ownerId)).thenReturn(false);

        assertThrows(ForbiddenException.class,
                () -> credentialService.create(request, ownerId));
        verify(credentialRepository, never()).save(any());
        verify(encryptionService, never()).encrypt(any());
    }

    @Test
    void findAllByVault_shouldThrow_whenVaultDoesNotBelongToOwner() {
        when(vaultRepository.existsByIdAndOwnerId(vaultId, ownerId)).thenReturn(false);

        assertThrows(ForbiddenException.class,
                () -> credentialService.findAllByVault(vaultId, ownerId));
    }

    @Test
    void findAllByVault_shouldReturnCredentials_whenOwnerIsValid() {
        Credential c1 = Credential.builder().id(UUID.randomUUID()).serviceName("GitHub")
                .username("u1").encryptedPassword("enc").vault(vault).build();
        Credential c2 = Credential.builder().id(UUID.randomUUID()).serviceName("Gmail")
                .username("u2").encryptedPassword("enc").vault(vault).build();

        when(vaultRepository.existsByIdAndOwnerId(vaultId, ownerId)).thenReturn(true);
        when(credentialRepository.findAllByVaultIdAndVaultOwnerId(vaultId, ownerId))
                .thenReturn(List.of(c1, c2));

        List<CredentialResponse> result = credentialService.findAllByVault(vaultId, ownerId);

        assertEquals(2, result.size());
    }

    @Test
    void findById_shouldReturnCredential_whenOwnerIsValid() {
        UUID credId = UUID.randomUUID();
        Credential credential = Credential.builder()
                .id(credId).serviceName("GitHub").username("user@email.com")
                .encryptedPassword("encryptedValue").url("https://github.com").vault(vault).build();
        when(credentialRepository.findByIdAndVaultOwnerId(credId, ownerId))
                .thenReturn(Optional.of(credential));

        CredentialResponse response = credentialService.findById(credId, ownerId);

        assertNotNull(response);
        assertEquals(credId, response.id());
        assertEquals("GitHub", response.serviceName());
        assertEquals(vaultId, response.vaultId());
    }

    @Test
    void create_shouldNotExposePasswordInResponse() {
        CreateCredentialRequest request = new CreateCredentialRequest(
                vaultId, "GitHub", "user@email.com", "plainPassword", "https://github.com", null);

        Credential saved = Credential.builder()
                .id(UUID.randomUUID()).serviceName("GitHub").username("user@email.com")
                .encryptedPassword("encryptedValue").url("https://github.com").vault(vault).build();

        when(vaultRepository.existsByIdAndOwnerId(vaultId, ownerId)).thenReturn(true);
        when(vaultRepository.getReferenceById(vaultId)).thenReturn(vault);
        when(encryptionService.encrypt("plainPassword")).thenReturn("encryptedValue");
        when(credentialRepository.save(any(Credential.class))).thenReturn(saved);

        CredentialResponse response = credentialService.create(request, ownerId);

        assertNotNull(response);
        // CredentialResponse must not expose any password field
        var fieldNames = Arrays.stream(CredentialResponse.class.getDeclaredFields())
                .map(java.lang.reflect.Field::getName)
                .toList();
        assertFalse(fieldNames.contains("password"), "CredentialResponse must not expose 'password'");
        assertFalse(fieldNames.contains("encryptedPassword"), "CredentialResponse must not expose 'encryptedPassword'");
    }

    @Test
    void findById_shouldThrow_whenCredentialDoesNotBelongToOwner() {
        UUID credId = UUID.randomUUID();
        when(credentialRepository.findByIdAndVaultOwnerId(credId, ownerId))
                .thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> credentialService.findById(credId, ownerId));
    }

    @Test
    void delete_shouldThrow_whenCredentialDoesNotBelongToOwner() {
        UUID credId = UUID.randomUUID();
        when(credentialRepository.existsByIdAndVaultOwnerId(credId, ownerId)).thenReturn(false);

        assertThrows(ForbiddenException.class,
                () -> credentialService.delete(credId, ownerId));
        verify(credentialRepository, never()).deleteById(any());
    }

    @Test
    void delete_shouldDeleteAndAudit_whenOwnerIsValid() {
        UUID credId = UUID.randomUUID();
        when(credentialRepository.existsByIdAndVaultOwnerId(credId, ownerId)).thenReturn(true);

        credentialService.delete(credId, ownerId);

        verify(credentialRepository).deleteById(credId);
        verify(auditService).log(any(), eq("testuser"), any(), any());
    }
}
