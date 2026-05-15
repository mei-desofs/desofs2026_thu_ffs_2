package com.kryptos.trusteddevice.application;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.trusteddevice.application.dto.RegisterDeviceRequest;
import com.kryptos.trusteddevice.application.dto.TrustedDeviceResponse;
import com.kryptos.trusteddevice.domain.TrustedDeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TrustedDeviceService {

    private final TrustedDeviceRepository trustedDeviceRepository;
    private final AuditService auditService;

    public TrustedDeviceResponse register(RegisterDeviceRequest request, UUID userId) {
        // TODO
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.DEVICE_REGISTER, username, "trusteddevice",
                "Registered device: " + request.deviceName());
        return null;
    }

    public List<TrustedDeviceResponse> findAllByUser(UUID userId) {
        // TODO
        return List.of();
    }

    public void revoke(UUID deviceId, UUID userId) {
        // TODO: verify ownership before revoking
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.DEVICE_REVOKE, username, "trusteddevice",
                "Revoked device: " + deviceId);
    }
}
