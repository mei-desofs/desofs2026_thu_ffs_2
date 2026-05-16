package com.kryptos.filehandling.application.dto;

public record CredentialExportRecord(
        String serviceName,
        String username,
        String password,
        String url,
        String notes,
        String vaultName
) {}
