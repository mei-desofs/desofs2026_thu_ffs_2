package com.kryptos.auth.application.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordResetConfirm(
    @NotBlank(message = "Reset token is required")
    String token,

    @NotBlank(message = "New password is required")
    @Size(min = 12, message = "Password must be at least 12 characters")
    String newPassword
) {}
