package com.kryptos.auth.application.dto;

import java.util.List;

public record BackupCodesResponse(
        List<String> codes,
        String message
) {}
