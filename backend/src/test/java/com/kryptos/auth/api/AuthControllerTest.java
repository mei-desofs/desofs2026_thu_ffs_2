package com.kryptos.auth.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptos.auth.application.AuthService;
import com.kryptos.auth.application.dto.AuthResponse;
import com.kryptos.auth.application.dto.BackupCodeVerifyRequest;
import com.kryptos.auth.application.dto.LoginRequest;
import com.kryptos.auth.application.dto.LoginResponse;
import com.kryptos.auth.application.dto.RegisterRequest;
import com.kryptos.auth.application.dto.TotpVerifyRequest;
import com.kryptos.auth.application.dto.TwoFaVerifyRequest;
import com.kryptos.shared.security.JwtService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtService jwtService;

    @Test
    void login_shouldSucceed_whenCredentialsInBody() throws Exception {
        LoginRequest request = new LoginRequest("user", "password123");
        when(authService.login(any(LoginRequest.class), eq(null), any(), any()))
                .thenReturn(LoginResponse.authenticated("token", "user", "USER"));

        mockMvc.perform(post("/api/auth/login")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(authService).login(any(LoginRequest.class), eq(null), any(), any());
    }

    @Test
    void login_shouldIgnoreSensitiveDataInQueryParams() throws Exception {
        mockMvc.perform(post("/api/auth/login?username=user&password=password123")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().is5xxServerError());

        verify(authService, never()).login(any(), any(), any(), any());
    }

    @Test
    void register_shouldSucceed_whenDataInBody() throws Exception {
        RegisterRequest request = new RegisterRequest("user", "user@test.com", "SecurePassword123!");
        when(authService.register(any(RegisterRequest.class), any(), any()))
                .thenReturn(new AuthResponse("token", "user", "USER"));

        mockMvc.perform(post("/api/auth/register")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(authService).register(any(RegisterRequest.class), any(), any());
    }

    @Test
    void register_shouldIgnoreSensitiveDataInQueryParams() throws Exception {
        mockMvc.perform(post("/api/auth/register?username=user&email=user@test.com&password=SecurePassword123!")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().is5xxServerError());

        verify(authService, never()).register(any(), any(), any());
    }

    @Test
    void twoFaVerify_shouldSucceed_whenDataInBody() throws Exception {
        TwoFaVerifyRequest request = new TwoFaVerifyRequest("user", "123456");
        when(authService.verifyTwoFaCode(any(TwoFaVerifyRequest.class), any(), any()))
                .thenReturn(new AuthResponse("token", "user", "USER"));

        mockMvc.perform(post("/api/auth/2fa/verify")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(authService).verifyTwoFaCode(any(TwoFaVerifyRequest.class), any(), any());
    }

    @Test
    void twoFaVerify_shouldIgnoreSensitiveDataInQueryParams() throws Exception {
        mockMvc.perform(post("/api/auth/2fa/verify?username=user&code=123456")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().is5xxServerError());

        verify(authService, never()).verifyTwoFaCode(any(), any(), any());
    }

    @Test
    void backupCodeVerify_shouldSucceed_whenDataInBody() throws Exception {
        BackupCodeVerifyRequest request = new BackupCodeVerifyRequest("user", "backup-code-123");
        when(authService.verifyBackupCode(any(BackupCodeVerifyRequest.class), any(), any()))
                .thenReturn(new AuthResponse("token", "user", "USER"));

        mockMvc.perform(post("/api/auth/2fa/verify-backup-code")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(authService).verifyBackupCode(any(BackupCodeVerifyRequest.class), any(), any());
    }

    @Test
    void backupCodeVerify_shouldIgnoreSensitiveDataInQueryParams() throws Exception {
        mockMvc.perform(post("/api/auth/2fa/verify-backup-code?username=user&backupCode=backup-code-123")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().is5xxServerError());

        verify(authService, never()).verifyBackupCode(any(), any(), any());
    }

    @Test
    void totpVerify_shouldSucceed_whenDataInBody() throws Exception {
        TotpVerifyRequest request = new TotpVerifyRequest("user", "123456");
        when(authService.verifyTotp(any(TotpVerifyRequest.class), any(), any()))
                .thenReturn(new AuthResponse("token", "user", "USER"));

        mockMvc.perform(post("/api/auth/totp/verify")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        verify(authService).verifyTotp(any(TotpVerifyRequest.class), any(), any());
    }

    @Test
    void totpVerify_shouldIgnoreSensitiveDataInQueryParams() throws Exception {
        mockMvc.perform(post("/api/auth/totp/verify?username=user&code=123456")
                        .with(csrf()).with(user("user"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().is5xxServerError());

        verify(authService, never()).verifyTotp(any(), any(), any());
    }

    @Test
    void totpConfirm_shouldSucceed_whenSecretInHeader() throws Exception {
        mockMvc.perform(post("/api/auth/totp/confirm")
                        .with(csrf()).with(user("user"))
                        .header("X-TOTP-Secret", "base64secret")
                        .header("X-TOTP-Code", "123456"))
                .andExpect(status().isOk());
    }

    @Test
    void totpConfirm_shouldIgnoreSensitiveDataInQueryParams() throws Exception {
        mockMvc.perform(post("/api/auth/totp/confirm?secret=base64secret&code=123456")
                        .with(csrf()).with(user("user")))
                .andExpect(status().is5xxServerError());
    }
}
