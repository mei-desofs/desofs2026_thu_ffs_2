package com.kryptos.auth.application.dto;

import jakarta.validation.constraints.NotBlank;

public record TwoFaVerifyRequest(
        @NotBlank String username,
        @NotBlank String code
) {}
