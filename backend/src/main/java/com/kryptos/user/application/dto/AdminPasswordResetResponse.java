package com.kryptos.user.application.dto;

import java.util.UUID;

public record AdminPasswordResetResponse(
        UUID userId,
        String username,
        String message,
        String resetToken
) {}
