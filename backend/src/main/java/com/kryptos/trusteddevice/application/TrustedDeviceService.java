package com.kryptos.trusteddevice.application;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.trusteddevice.application.dto.RegisterDeviceRequest;
import com.kryptos.trusteddevice.application.dto.TrustedDeviceResponse;
import com.kryptos.trusteddevice.application.dto.UpdateDeviceRequest;
import com.kryptos.trusteddevice.domain.TrustedDevice;
import com.kryptos.trusteddevice.domain.TrustedDeviceRepository;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TrustedDeviceService {

    private final TrustedDeviceRepository trustedDeviceRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    @Transactional
    public TrustedDeviceResponse register(RegisterDeviceRequest request, UUID ownerId) {
        // Idempotent: same fingerprint for the same user re-activates the
        // existing row; same fingerprint for another user is refused.
        Optional<TrustedDevice> existing =
                trustedDeviceRepository.findByDeviceFingerprint(request.deviceFingerprint());
        if (existing.isPresent()) {
            TrustedDevice device = existing.get();
            if (!device.getUser().getId().equals(ownerId)) {
                auditService.log(AuditAction.DEVICE_REGISTER, currentUsername(),
                        "trusteddevice", "Device fingerprint collision rejected");
                throw new ForbiddenException("Device fingerprint already registered");
            }
            device.setDeviceName(request.deviceName());
            device.setActive(true);
            TrustedDevice saved = trustedDeviceRepository.save(device);
            auditService.log(AuditAction.DEVICE_REGISTER, currentUsername(),
                    "trusteddevice", "Re-activated device: " + saved.getId());
            return toResponse(saved);
        }

        User owner = userRepository.getReferenceById(ownerId);
        TrustedDevice device = TrustedDevice.builder()
                .deviceName(request.deviceName())
                .deviceFingerprint(request.deviceFingerprint())
                .registeredAt(LocalDateTime.now())
                .active(true)
                .user(owner)
                .build();
        TrustedDevice saved = trustedDeviceRepository.save(device);

        auditService.log(AuditAction.DEVICE_REGISTER, currentUsername(),
                "trusteddevice", "Registered device: " + saved.getId());
        return toResponse(saved);
    }

    public List<TrustedDeviceResponse> findAllByOwner(UUID ownerId) {
        return trustedDeviceRepository.findAllByUserId(ownerId).stream()
                .map(TrustedDeviceService::toResponse)
                .toList();
    }

    public TrustedDeviceResponse findById(UUID id, UUID ownerId) {
        TrustedDevice device = trustedDeviceRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Trusted device not found"));
        if (!device.getUser().getId().equals(ownerId)) {
            // Do not leak existence of a device that belongs to someone else.
            throw new ResourceNotFoundException("Trusted device not found");
        }
        return toResponse(device);
    }

    @Transactional
    public TrustedDeviceResponse updateName(UUID id, UpdateDeviceRequest request, UUID ownerId) {
        TrustedDevice device = trustedDeviceRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Trusted device not found"));
        if (!device.getUser().getId().equals(ownerId)) {
            auditService.log(AuditAction.DEVICE_UPDATE, currentUsername(),
                    "trusteddevice", "Forbidden update attempt on device: " + id);
            throw new ForbiddenException("You do not own this device");
        }
        device.setDeviceName(request.deviceName());
        TrustedDevice saved = trustedDeviceRepository.save(device);
        auditService.log(AuditAction.DEVICE_UPDATE, currentUsername(),
                "trusteddevice", "Renamed device: " + id);
        return toResponse(saved);
    }

    @Transactional
    public void revoke(UUID id, UUID ownerId) {
        TrustedDevice device = trustedDeviceRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Trusted device not found"));
        if (!device.getUser().getId().equals(ownerId)) {
            auditService.log(AuditAction.DEVICE_REVOKE, currentUsername(),
                    "trusteddevice", "Forbidden revoke attempt on device: " + id);
            throw new ForbiddenException("You do not own this device");
        }
        device.setActive(false);
        trustedDeviceRepository.save(device);
        auditService.log(AuditAction.DEVICE_REVOKE, currentUsername(),
                "trusteddevice", "Revoked device: " + id);
    }

    private static TrustedDeviceResponse toResponse(TrustedDevice device) {
        return new TrustedDeviceResponse(
                device.getId(), device.getDeviceName(), device.getDeviceFingerprint(),
                device.getRegisteredAt(), device.isActive());
    }

    private String currentUsername() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
