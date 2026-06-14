package com.kryptos.auth.application.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetConfirm(
    @NotBlank(message = "Token is required")
    String token,

    @NotBlank(message = "Password is required")
    @Size(min = 12, message = "Password must be at least 12 characters")
    String newPassword
) {}
