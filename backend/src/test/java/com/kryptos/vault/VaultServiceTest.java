package com.kryptos.vault;

import com.kryptos.audit.application.AuditService;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;
import com.kryptos.vault.application.VaultService;
import com.kryptos.vault.application.dto.CreateVaultRequest;
import com.kryptos.vault.application.dto.UpdateVaultRequest;
import com.kryptos.vault.application.dto.VaultResponse;
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

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VaultServiceTest {

    @Mock private VaultRepository vaultRepository;
    @Mock private UserRepository userRepository;
    @Mock private AuditService auditService;

    @InjectMocks
    private VaultService vaultService;

    private UUID ownerId;
    private User owner;

    @BeforeEach
    void setUp() {
        ownerId = UUID.randomUUID();
        owner = User.builder().id(ownerId).username("testuser").build();

        Authentication auth = mock(Authentication.class);
        lenient().when(auth.getName()).thenReturn("testuser");
        SecurityContext ctx = mock(SecurityContext.class);
        lenient().when(ctx.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(ctx);
    }

    @Test
    void create_shouldSaveAndReturnVault() {
        CreateVaultRequest request = new CreateVaultRequest("My Vault", "desc");
        Vault saved = Vault.builder()
                .id(UUID.randomUUID())
                .name("My Vault")
                .description("desc")
                .owner(owner)
                .build();

        when(userRepository.getReferenceById(ownerId)).thenReturn(owner);
        when(vaultRepository.save(any(Vault.class))).thenReturn(saved);

        VaultResponse response = vaultService.create(request, ownerId);

        assertNotNull(response);
        assertEquals("My Vault", response.name());
        assertEquals(ownerId, response.ownerId());
        verify(vaultRepository).save(any(Vault.class));
        verify(auditService).log(any(), eq("testuser"), any(), any());
    }

    @Test
    void findAllByOwner_shouldReturnOnlyOwnerVaults() {
        Vault v1 = Vault.builder().id(UUID.randomUUID()).name("V1").owner(owner).build();
        Vault v2 = Vault.builder().id(UUID.randomUUID()).name("V2").owner(owner).build();
        when(vaultRepository.findAllByOwnerId(ownerId)).thenReturn(List.of(v1, v2));

        List<VaultResponse> result = vaultService.findAllByOwner(ownerId);

        assertEquals(2, result.size());
        verify(vaultRepository).findAllByOwnerId(ownerId);
    }

    @Test
    void findById_shouldReturnVault_whenOwnerIsValid() {
        UUID vaultId = UUID.randomUUID();
        Vault vault = Vault.builder().id(vaultId).name("My Vault").description("desc").owner(owner).build();
        when(vaultRepository.findByIdAndOwnerId(vaultId, ownerId)).thenReturn(Optional.of(vault));

        VaultResponse response = vaultService.findById(vaultId, ownerId);

        assertNotNull(response);
        assertEquals(vaultId, response.id());
        assertEquals("My Vault", response.name());
        assertEquals(ownerId, response.ownerId());
    }

    @Test
    void findById_shouldThrow_whenVaultDoesNotBelongToOwner() {
        UUID vaultId = UUID.randomUUID();
        when(vaultRepository.findByIdAndOwnerId(vaultId, ownerId)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> vaultService.findById(vaultId, ownerId));
    }

    @Test
    void update_shouldUpdateAndReturnVault_whenOwnerIsValid() {
        UUID vaultId = UUID.randomUUID();
        Vault vault = Vault.builder().id(vaultId).name("Old Name").description("Old Desc").owner(owner).build();
        when(vaultRepository.findByIdAndOwnerId(vaultId, ownerId)).thenReturn(Optional.of(vault));
        when(vaultRepository.save(any(Vault.class))).thenReturn(vault);

        UpdateVaultRequest request = new UpdateVaultRequest("New Name", "New Desc");
        VaultResponse response = vaultService.update(vaultId, request, ownerId);

        assertNotNull(response);
        assertEquals("New Name", response.name());
        assertEquals("New Desc", response.description());
        verify(vaultRepository).save(vault);
        verify(auditService).log(any(), eq("testuser"), any(), any());
    }

    @Test
    void update_shouldThrow_whenVaultDoesNotBelongToOwner() {
        UUID vaultId = UUID.randomUUID();
        when(vaultRepository.findByIdAndOwnerId(vaultId, ownerId)).thenReturn(Optional.empty());

        UpdateVaultRequest request = new UpdateVaultRequest("Hacked", "Hacked");
        assertThrows(ForbiddenException.class,
                () -> vaultService.update(vaultId, request, ownerId));
        verify(vaultRepository, never()).save(any());
    }

    @Test
    void delete_shouldThrow_whenVaultDoesNotBelongToOwner() {
        UUID vaultId = UUID.randomUUID();
        when(vaultRepository.existsByIdAndOwnerId(vaultId, ownerId)).thenReturn(false);

        assertThrows(ForbiddenException.class,
                () -> vaultService.delete(vaultId, ownerId));
        verify(vaultRepository, never()).deleteById(any());
    }

    @Test
    void delete_shouldDeleteAndAudit_whenOwnerIsValid() {
        UUID vaultId = UUID.randomUUID();
        when(vaultRepository.existsByIdAndOwnerId(vaultId, ownerId)).thenReturn(true);

        vaultService.delete(vaultId, ownerId);

        verify(vaultRepository).deleteById(vaultId);
        verify(auditService).log(any(), eq("testuser"), any(), any());
    }
}
