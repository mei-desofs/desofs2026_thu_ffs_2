package com.kryptos.credential.application.dto;

import java.util.UUID;

public record CredentialResponse(
        UUID id,
        String serviceName,
        String username,
        String url,
        String notes,
        UUID vaultId
) {}
