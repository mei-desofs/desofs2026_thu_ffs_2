package com.kryptos.auth.application.dto;

public record TotpVerifyRequest(
        String username,
        String code
) {}
