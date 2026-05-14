package com.kryptos.vault.application.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateVaultRequest(
        @NotBlank @Size(max = 100) String name,
        String description
) {}
