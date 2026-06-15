package com.kryptos.auth.application.dto;

public record TotpSetupResponse(
        String secret,
        String qrCode,
        String message
) {}
