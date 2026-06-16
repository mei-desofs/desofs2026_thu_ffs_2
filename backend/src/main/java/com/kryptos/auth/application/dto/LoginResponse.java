package com.kryptos.auth.application.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoginResponse(
        String status,
        String token,
        String username,
        String role,
        String message
) {
    public static LoginResponse twoFaRequired(String username) {
        return new LoginResponse("2fa_required", null, username, null,
                "A verification code has been sent to your email");
    }

    public static LoginResponse authenticated(String token, String username, String role) {
        return new LoginResponse("authenticated", token, username, role, null);
    }
}
