package com.kryptos.auth;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.auth.application.AuthService;
import com.kryptos.auth.application.dto.AuthResponse;
import com.kryptos.auth.application.dto.LoginRequest;
import com.kryptos.auth.application.dto.LoginResponse;
import com.kryptos.auth.application.dto.PasswordResetConfirm;
import com.kryptos.auth.application.dto.RegisterRequest;
import com.kryptos.auth.application.dto.TwoFaVerifyRequest;
import com.kryptos.shared.email.EmailService;
import com.kryptos.shared.exception.InvalidTokenException;
import com.kryptos.shared.exception.RateLimitExceededException;
import com.kryptos.shared.security.JwtService;
import com.kryptos.auth.application.dto.PasswordResetRequest;
import com.kryptos.shared.exception.ReauthenticationRequiredException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private JwtService jwtService;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private AuditService auditService;
    @Mock private EmailService emailService;

    @InjectMocks
    private AuthService authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("UserTest")
                .email("test@kryptos.com")
                .password("encoded_password")
                .role(Role.USER)
                .active(true)
                .build();
    }

    @Test
    void register_shouldReturnToken_whenValidRequest() {
        RegisterRequest request = new RegisterRequest("UserTest", "test@kryptos.com", "password123");

        when(userRepository.findByEmail(request.email())).thenReturn(Optional.empty());
        when(userRepository.findByUsername(request.username())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(request.password())).thenReturn("encoded_password");
        when(jwtService.generateToken(anyString(), anyString(), anyString(), anyString())).thenReturn("mock.jwt.token");

        AuthResponse response = authService.register(request, "127.0.0.1", "TestAgent");

        assertNotNull(response);
        assertEquals("mock.jwt.token", response.token());
        assertEquals("UserTest", response.username());
        assertEquals("USER", response.role());

        verify(userRepository).save(any(User.class));
        verify(auditService).log(eq(AuditAction.REGISTER), eq("UserTest"), eq("auth"), any());
    }

    @Test
    void register_shouldThrowException_whenUsernameOrEmailExists() {
        RegisterRequest request = new RegisterRequest("UserTest", "test@kryptos.com", "password123");
        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(testUser));

        assertThrows(IllegalArgumentException.class, () -> authService.register(request, "127.0.0.1", "TestAgent"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void login_shouldReturnToken_whenValidCredentials_and2faDisabled() {
        LoginRequest request = new LoginRequest("UserTest", "password123");

        when(userRepository.findByUsername(request.username())).thenReturn(Optional.of(testUser));
        when(jwtService.generateToken("UserTest", "USER", "127.0.0.1", "TestAgent")).thenReturn("mock.jwt.token");

        LoginResponse response = authService.login(request, null, "127.0.0.1", "TestAgent");

        assertNotNull(response);
        assertEquals("authenticated", response.status());
        assertEquals("mock.jwt.token", response.token());

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(auditService).log(eq(AuditAction.LOGIN), eq("UserTest"), eq("auth"), any());
    }

    @Test
    void login_shouldReturn2faRequired_when2faEnabled() {
        testUser.setTwoFaEnabled(true);
        LoginRequest request = new LoginRequest("UserTest", "password123");

        when(userRepository.findByUsername(request.username())).thenReturn(Optional.of(testUser));

        LoginResponse response = authService.login(request, null, "127.0.0.1", "TestAgent");

        assertEquals("2fa_required", response.status());
        assertNull(response.token());
        assertEquals("UserTest", response.username());

        verify(emailService).sendTwoFaCode(eq("test@kryptos.com"), anyString());
        verify(userRepository, atLeast(1)).save(any(User.class));
    }

    @Test
    void verifyTwoFaCode_shouldReturnToken_whenCodeValid() {
        testUser.setTwoFaEnabled(true);
        testUser.setTwoFaCode("123456");
        testUser.setTwoFaCodeExpiresAt(LocalDateTime.now().plusMinutes(5));

        TwoFaVerifyRequest request = new TwoFaVerifyRequest("UserTest", "123456");

        when(userRepository.findByUsername("UserTest")).thenReturn(Optional.of(testUser));
        when(jwtService.generateToken("UserTest", "USER", "127.0.0.1", "TestAgent")).thenReturn("mock.jwt.token");

        AuthResponse response = authService.verifyTwoFaCode(request, "127.0.0.1", "TestAgent");

        assertEquals("mock.jwt.token", response.token());
        assertNull(testUser.getTwoFaCode());
        assertNull(testUser.getTwoFaCodeExpiresAt());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void verifyTwoFaCode_shouldFail_whenCodeInvalid() {
        testUser.setTwoFaEnabled(true);
        testUser.setTwoFaCode("123456");
        testUser.setTwoFaCodeExpiresAt(LocalDateTime.now().plusMinutes(5));

        TwoFaVerifyRequest request = new TwoFaVerifyRequest("UserTest", "999999");

        when(userRepository.findByUsername("UserTest")).thenReturn(Optional.of(testUser));

        assertThrows(IllegalArgumentException.class, () -> authService.verifyTwoFaCode(request, "127.0.0.1", "TestAgent"));
    }

    @Test
    void verifyTwoFaCode_shouldFail_whenCodeExpired() {
        testUser.setTwoFaEnabled(true);
        testUser.setTwoFaCode("123456");
        testUser.setTwoFaCodeExpiresAt(LocalDateTime.now().minusMinutes(1));

        TwoFaVerifyRequest request = new TwoFaVerifyRequest("UserTest", "123456");

        when(userRepository.findByUsername("UserTest")).thenReturn(Optional.of(testUser));

        assertThrows(Exception.class, () -> authService.verifyTwoFaCode(request, "127.0.0.1", "TestAgent"));
    }

    @Test
    void login_shouldFail_whenWrongPassword() {
        LoginRequest request = new LoginRequest("UserTest", "wrongpassword");

        when(userRepository.findByUsername(request.username())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> authService.login(request, null, "127.0.0.1", "TestAgent"));

        assertEquals("Invalid credentials", ex.getMessage());
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(auditService).log(eq(AuditAction.LOGIN_FAILED), eq("UserTest"), eq("auth"), any());
    }

    @Test
    void login_shouldLockAccount_afterMaxFailedAttempts() {
        LoginRequest request = new LoginRequest("UserTest", "wrongpassword");

        when(userRepository.findByUsername(request.username())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        for (int i = 0; i < 5; i++) {
            assertThrows(IllegalArgumentException.class, () -> authService.login(request, null, "127.0.0.1", "TestAgent"));
        }

        RateLimitExceededException ex = assertThrows(RateLimitExceededException.class,
                () -> authService.login(request, null, "127.0.0.1", "TestAgent"));

        assertTrue(ex.getMessage().contains("Too many failed attempts"));
        verify(auditService, atLeast(5)).log(eq(AuditAction.LOGIN_FAILED), eq("UserTest"), eq("auth"), any());
    }

    @Test
    void confirmPasswordReset_shouldThrow_whenPasswordInHistory() {
        String resetToken = UUID.randomUUID().toString();
        String oldPasswordHash = "hash_of_old_password";
        testUser.setResetToken(resetToken);
        testUser.setResetTokenExpiresAt(LocalDateTime.now().plusMinutes(15));
        testUser.addToPasswordHistory(oldPasswordHash);

        PasswordResetConfirm confirm = new PasswordResetConfirm(resetToken, "SamePassword123!");

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("SamePassword123!", oldPasswordHash)).thenReturn(true);

        assertThrows(IllegalArgumentException.class,
                () -> authService.confirmPasswordReset(confirm));
    }

    @Test
    void confirmPasswordReset_shouldAddOldPasswordToHistory() {
        String resetToken = UUID.randomUUID().toString();
        testUser.setResetToken(resetToken);
        testUser.setResetTokenExpiresAt(LocalDateTime.now().plusMinutes(15));
        testUser.setPassword("old_hash");

        PasswordResetConfirm confirm = new PasswordResetConfirm(resetToken, "NewPassword123!");

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.encode("NewPassword123!")).thenReturn("new_hash");

        authService.confirmPasswordReset(confirm);

        verify(userRepository).save(any(User.class));
        verify(auditService).log(eq(AuditAction.PASSWORD_RESET_COMPLETED), eq("UserTest"), eq("auth"), any());
        assertTrue(testUser.getPasswordHistory().contains("old_hash"));
    }

    @Test
    void login_shouldBlockAccess_whenAccountLockedUntilAdmin() {
        testUser.setAccountLockedUntilAdmin(true);
        LoginRequest request = new LoginRequest("UserTest", "password123");

        when(userRepository.findByUsername(request.username())).thenReturn(Optional.of(testUser));

        RateLimitExceededException ex = assertThrows(RateLimitExceededException.class,
                () -> authService.login(request, null, "127.0.0.1", "TestAgent"));

        assertTrue(ex.getMessage().contains("Account locked"));
        verify(auditService).log(eq(AuditAction.LOGIN_FAILED), eq("UserTest"), eq("auth"), any());
    }

    @Test
    void requestPasswordReset_shouldThrow_whenTooManyAttempts() {
        String email = "test@kryptos.com";
        PasswordResetRequest request = new PasswordResetRequest(email);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(testUser));

        for (int i = 0; i < 3; i++) {
            authService.requestPasswordReset(request);
        }

        RateLimitExceededException ex = assertThrows(RateLimitExceededException.class,
                () -> authService.requestPasswordReset(request));

        assertTrue(ex.getMessage().contains("Too many password reset requests"));
        verify(auditService, atLeast(4)).log(eq(AuditAction.PASSWORD_RESET_REQUESTED), eq(email), eq("auth"), any());
    }

    @Test
    void confirmPasswordReset_shouldThrow_whenTokenExpired() {
        String resetToken = UUID.randomUUID().toString();
        testUser.setResetToken(resetToken);
        testUser.setResetTokenExpiresAt(java.time.LocalDateTime.now().minusMinutes(1));

        PasswordResetConfirm confirm = new PasswordResetConfirm(resetToken, "NewPassword123!");

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.of(testUser));

        assertThrows(InvalidTokenException.class, () -> authService.confirmPasswordReset(confirm));
    }

    @Test
    void confirmPasswordReset_shouldThrow_whenTokenNotFound() {
        String resetToken = UUID.randomUUID().toString();

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.empty());

        PasswordResetConfirm confirm = new PasswordResetConfirm(resetToken, "NewPassword123!");

        assertThrows(InvalidTokenException.class, () -> authService.confirmPasswordReset(confirm));
    }

    @Test
    void requestPasswordReset_shouldThrow_whenUserNotFound() {
        String email = "nonexistent@kryptos.com";
        PasswordResetRequest request = new PasswordResetRequest(email);

        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> authService.requestPasswordReset(request));
    }

    @Test
    void confirmPasswordReset_shouldNotReusePassword_fromHistory() {
        String resetToken = UUID.randomUUID().toString();
        String oldPasswordHash = "hash_of_old_password";

        testUser.setResetToken(resetToken);
        testUser.setResetTokenExpiresAt(java.time.LocalDateTime.now().plusMinutes(15));
        testUser.addToPasswordHistory(oldPasswordHash);

        PasswordResetConfirm confirm = new PasswordResetConfirm(resetToken, "OldPassword123");

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("OldPassword123", oldPasswordHash)).thenReturn(true);

        assertThrows(IllegalArgumentException.class,
                () -> authService.confirmPasswordReset(confirm),
                "Should not allow reusing old passwords");
    }

    @Test
    void register_shouldThrow_whenEmailAlreadyExists() {
        RegisterRequest request = new RegisterRequest("NewUser", "test@kryptos.com", "password123");

        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(testUser));

        assertThrows(IllegalArgumentException.class, () -> authService.register(request, "127.0.0.1", "TestAgent"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void register_shouldThrow_whenUsernameAlreadyExists() {
        RegisterRequest request = new RegisterRequest("UserTest", "new@kryptos.com", "password123");

        when(userRepository.findByEmail(request.email())).thenReturn(Optional.empty());
        when(userRepository.findByUsername(request.username())).thenReturn(Optional.of(testUser));

        assertThrows(IllegalArgumentException.class, () -> authService.register(request, "127.0.0.1", "TestAgent"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void enableTwoFa_shouldThrowReauthenticationRequiredException_whenTokenIsStale() {
        org.mockito.Mockito.doThrow(new ReauthenticationRequiredException("Stale token"))
                .when(jwtService).requireRecentAuthentication();

        assertThrows(ReauthenticationRequiredException.class,
                () -> authService.enableTwoFa("UserTest"));
    }

    @Test
    void disableTwoFa_shouldThrowReauthenticationRequiredException_whenTokenIsStale() {
        org.mockito.Mockito.doThrow(new ReauthenticationRequiredException("Stale token"))
                .when(jwtService).requireRecentAuthentication();

        assertThrows(ReauthenticationRequiredException.class,
                () -> authService.disableTwoFa("UserTest"));
    }
}
