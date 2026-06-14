package com.kryptos.auth.application.dto;

import jakarta.validation.constraints.Email;

public record PasswordResetRequest(
    @Email(message = "Invalid email format")
    String email
) {}
