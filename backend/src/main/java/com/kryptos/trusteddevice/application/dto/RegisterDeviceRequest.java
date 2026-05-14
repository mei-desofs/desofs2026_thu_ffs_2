package com.kryptos.trusteddevice.application.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterDeviceRequest(
        @NotBlank @Size(max = 100) String deviceName,
        @NotBlank String deviceFingerprint
) {}
