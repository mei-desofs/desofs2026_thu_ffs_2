package com.kryptos.trusteddevice;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.trusteddevice.application.TrustedDeviceService;
import com.kryptos.trusteddevice.application.dto.RegisterDeviceRequest;
import com.kryptos.trusteddevice.application.dto.TrustedDeviceResponse;
import com.kryptos.trusteddevice.application.dto.UpdateDeviceRequest;
import com.kryptos.trusteddevice.domain.TrustedDevice;
import com.kryptos.trusteddevice.domain.TrustedDeviceRepository;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TrustedDeviceServiceTest {

    @Mock private TrustedDeviceRepository trustedDeviceRepository;
    @Mock private UserRepository userRepository;
    @Mock private AuditService auditService;

    @InjectMocks
    private TrustedDeviceService service;

    private UUID ownerId;
    private User owner;

    @BeforeEach
    void setUp() {
        ownerId = UUID.randomUUID();
        owner = User.builder().id(ownerId).username("alice").build();

        Authentication auth = mock(Authentication.class);
        lenient().when(auth.getName()).thenReturn("alice");
        SecurityContext ctx = mock(SecurityContext.class);
        lenient().when(ctx.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(ctx);
    }

    @Test
    void register_shouldCreateNewDevice_whenFingerprintNotSeenBefore() {
        when(trustedDeviceRepository.findByDeviceFingerprint("fp-1")).thenReturn(Optional.empty());
        when(userRepository.getReferenceById(ownerId)).thenReturn(owner);
        when(trustedDeviceRepository.save(any(TrustedDevice.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        TrustedDeviceResponse response = service.register(
                new RegisterDeviceRequest("Macbook", "fp-1"), ownerId);

        assertEquals("Macbook", response.deviceName());
        assertTrue(response.active());
        verify(auditService).log(eq(AuditAction.DEVICE_REGISTER), eq("alice"), eq("trusteddevice"), any());
    }

    @Test
    void register_shouldRejectFingerprintOwnedByAnotherUser() {
        // R17 — rogue device registration via fingerprint collision.
        User stranger = User.builder().id(UUID.randomUUID()).username("bob").build();
        TrustedDevice existing = TrustedDevice.builder()
                .id(UUID.randomUUID())
                .deviceFingerprint("fp-shared")
                .user(stranger)
                .build();
        when(trustedDeviceRepository.findByDeviceFingerprint("fp-shared"))
                .thenReturn(Optional.of(existing));

        assertThrows(ForbiddenException.class, () -> service.register(
                new RegisterDeviceRequest("Mine", "fp-shared"), ownerId));
        verify(trustedDeviceRepository, never()).save(any());
        verify(auditService).log(eq(AuditAction.DEVICE_REGISTER), eq("alice"), eq("trusteddevice"), any());
    }

    @Test
    void findById_shouldThrowNotFound_whenCallerIsNotOwner_idorSafe() {
        // R05/R07 — IDOR mitigation: surface as 404 (no existence leak).
        UUID deviceId = UUID.randomUUID();
        User stranger = User.builder().id(UUID.randomUUID()).build();
        when(trustedDeviceRepository.findById(deviceId))
                .thenReturn(Optional.of(TrustedDevice.builder().id(deviceId).user(stranger).build()));

        assertThrows(ResourceNotFoundException.class,
                () -> service.findById(deviceId, ownerId));
    }

    @Test
    void revoke_shouldDeactivateDeviceAndAudit() {
        UUID deviceId = UUID.randomUUID();
        TrustedDevice device = TrustedDevice.builder()
                .id(deviceId).deviceName("Macbook").deviceFingerprint("fp-1")
                .active(true).user(owner).build();
        when(trustedDeviceRepository.findById(deviceId)).thenReturn(Optional.of(device));

        service.revoke(deviceId, ownerId);

        assertFalse(device.isActive());
        verify(trustedDeviceRepository).save(device);
        verify(auditService).log(eq(AuditAction.DEVICE_REVOKE), eq("alice"), eq("trusteddevice"), any());
    }

    @Test
    void revoke_shouldAudit_whenCallerIsNotOwner() {
        UUID deviceId = UUID.randomUUID();
        User stranger = User.builder().id(UUID.randomUUID()).username("bob").build();
        TrustedDevice device = TrustedDevice.builder()
                .id(deviceId).deviceName("Macbook").deviceFingerprint("fp-1")
                .active(true).user(stranger).build();
        when(trustedDeviceRepository.findById(deviceId)).thenReturn(Optional.of(device));

        assertThrows(ForbiddenException.class, () -> service.revoke(deviceId, ownerId));
        verify(auditService).log(eq(AuditAction.DEVICE_REVOKE), eq("alice"), eq("trusteddevice"), any());
    }

    @Test
    void updateName_shouldUpdateAndAudit() {
        UUID deviceId = UUID.randomUUID();
        TrustedDevice device = TrustedDevice.builder()
                .id(deviceId).deviceName("Old Name").deviceFingerprint("fp-1")
                .active(true).user(owner).build();
        when(trustedDeviceRepository.findById(deviceId)).thenReturn(Optional.of(device));
        when(trustedDeviceRepository.save(any(TrustedDevice.class))).thenAnswer(inv -> inv.getArgument(0));

        UpdateDeviceRequest req = new UpdateDeviceRequest("New Name");
        TrustedDeviceResponse response = service.updateName(deviceId, req, ownerId);

        assertEquals("New Name", response.deviceName());
        verify(auditService).log(eq(AuditAction.DEVICE_UPDATE), eq("alice"), eq("trusteddevice"), any());
    }
}
