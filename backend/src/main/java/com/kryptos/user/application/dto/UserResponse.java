package com.kryptos.user.application.dto;

import com.kryptos.user.domain.Role;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String username,
        String email,
        Role role
) {}
