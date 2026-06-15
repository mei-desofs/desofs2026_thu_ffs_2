package com.kryptos.auth.application.dto;

import java.time.LocalDateTime;

public record SuspiciousAuthAttempt(
        String username,
        String email,
        String reason,
        String ipAddress,
        String userAgent,
        LocalDateTime attemptedAt
) {}
