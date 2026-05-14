package com.kryptos.auth.application.dto;

public record AuthResponse(
        String token,
        String username,
        String role
) {}
