package com.kryptos.trusteddevice.application.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public record TrustedDeviceResponse(
        UUID id,
        String deviceName,
        String deviceFingerprint,
        LocalDateTime registeredAt,
        boolean active
) {}
