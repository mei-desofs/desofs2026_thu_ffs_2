package com.kryptos.auth.application.dto;

public record BackupCodeVerifyRequest(
        String username,
        String backupCode
) {}
