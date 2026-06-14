package com.kryptos.user.application.dto;

import jakarta.validation.constraints.*;

public record UpdateUserRequest(
    @Email(message = "Email must be valid")
    String email,

    @NotBlank(message = "Username cannot be blank")
    @Size(min = 3, max = 50, message = "Username must be 3-50 chars")
    String username
) {
    public UpdateUserRequest {
        // Permite nulos para fazer updates parciais
    }
}
