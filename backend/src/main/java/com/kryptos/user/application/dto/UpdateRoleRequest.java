package com.kryptos.user.application.dto;
import com.kryptos.user.domain.Role;

import jakarta.validation.constraints.NotNull;

public record UpdateRoleRequest(@NotNull Role role) {}