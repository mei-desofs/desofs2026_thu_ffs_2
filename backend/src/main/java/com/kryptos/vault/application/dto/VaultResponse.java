package com.kryptos.vault.application.dto;

import java.util.UUID;

public record VaultResponse(
        UUID id,
        String name,
        String description,
        UUID ownerId
) {}
