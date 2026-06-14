package com.kryptos.credential.application.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateCredentialRequest(
        @NotBlank @Size(max = 100) String serviceName,
        @NotBlank @Size(max = 100) String username,
        @NotBlank @Size(min = 1, max = 500) String password,
        String url,
        String notes
) {}
