package com.kryptos.auth.application.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record PasswordResetRequest(
    @Email(message = "Email must be valid")
    @NotBlank(message = "Email is required")
    String email
) {}
