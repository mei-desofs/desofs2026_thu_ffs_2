package com.kryptos.trusteddevice.application.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;


public record UpdateDeviceRequest(
        @NotBlank @Size(max = 100) String deviceName
) {}
