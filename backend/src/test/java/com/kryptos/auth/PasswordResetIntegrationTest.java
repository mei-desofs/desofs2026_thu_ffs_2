package com.kryptos.auth;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.auth.application.AuthExpiryNotificationService;
import com.kryptos.auth.application.AuthService;
import com.kryptos.auth.application.BackupCodeService;
import com.kryptos.auth.application.SuspiciousAuthNotificationService;
import com.kryptos.auth.application.TotpService;
import com.kryptos.auth.application.dto.PasswordResetConfirm;
import com.kryptos.auth.application.dto.PasswordResetRequest;
import com.kryptos.shared.email.EmailService;
import com.kryptos.shared.exception.InvalidTokenException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.shared.security.JwtService;
import com.kryptos.trusteddevice.domain.TrustedDeviceRepository;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;

@ExtendWith(MockitoExtension.class)
class PasswordResetIntegrationTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private AuditService auditService;

    @Mock
    private EmailService emailService;

    @Mock
    private TrustedDeviceRepository trustedDeviceRepository;

    @Mock
    private SuspiciousAuthNotificationService suspiciousAuthNotificationService;

    @Mock
    private AuthExpiryNotificationService authExpiryNotificationService;

    @Mock
    private BackupCodeService backupCodeService;

    @Mock
    private TotpService totpService;

    @InjectMocks
    private AuthService authService;

    private User testUser;
    private UUID userId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        testUser = User.builder()
                .id(userId)
                .username("testuser")
                .email("test@kryptos.com")
                .password("hashedpassword")
                .role(Role.USER)
                .active(true)
                .build();
    }

    @Test
    void requestPasswordReset_shouldCreateToken() {
        when(userRepository.findByEmail("test@kryptos.com")).thenReturn(Optional.of(testUser));

        authService.requestPasswordReset(new PasswordResetRequest("test@kryptos.com"));

        assertNotNull(testUser.getResetToken());
        assertNotNull(testUser.getResetTokenExpiresAt());
        verify(userRepository).save(testUser);
        verify(auditService).log(eq(AuditAction.PASSWORD_RESET_REQUESTED), eq("test@kryptos.com"), eq("auth"), anyString());
    }

    @Test
    void requestPasswordReset_shouldSetExpirationTo15Minutes() {
        when(userRepository.findByEmail("test@kryptos.com")).thenReturn(Optional.of(testUser));

        authService.requestPasswordReset(new PasswordResetRequest("test@kryptos.com"));

        LocalDateTime expiresAt = testUser.getResetTokenExpiresAt();
        LocalDateTime now = LocalDateTime.now();

        // Check expiration is approximately 15 minutes in future (allow 1 minute tolerance)
        long secondsUntilExpiry = java.time.temporal.ChronoUnit.SECONDS.between(now, expiresAt);
        assertEquals(900, secondsUntilExpiry, 60); // 900 seconds = 15 minutes
    }

    @Test
    void requestPasswordReset_shouldThrow_whenUserNotFound() {
        when(userRepository.findByEmail("notfound@test.com")).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> authService.requestPasswordReset(new PasswordResetRequest("notfound@test.com")));
    }

    @Test
    void confirmPasswordReset_shouldUpdatePassword() {
        String resetToken = UUID.randomUUID().toString();
        testUser.setResetToken(resetToken);
        testUser.setResetTokenExpiresAt(LocalDateTime.now().plusMinutes(15));

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.encode("SecureVault9$x")).thenReturn("hashedNewPassword");

        authService.confirmPasswordReset(new PasswordResetConfirm(resetToken, "SecureVault9$x"));

        assertEquals("hashedNewPassword", testUser.getPassword());
        assertNull(testUser.getResetToken());
        assertNull(testUser.getResetTokenExpiresAt());
        verify(userRepository).save(testUser);
        verify(auditService).log(eq(AuditAction.PASSWORD_RESET_COMPLETED), eq("testuser"), eq("auth"), anyString());
    }

    @Test
    void confirmPasswordReset_shouldThrow_whenTokenExpired() {
        String resetToken = UUID.randomUUID().toString();
        testUser.setResetToken(resetToken);
        testUser.setResetTokenExpiresAt(LocalDateTime.now().minusMinutes(1));

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.of(testUser));

        assertThrows(InvalidTokenException.class,
                () -> authService.confirmPasswordReset(new PasswordResetConfirm(resetToken, "SecureVault9$x")));
    }

    @Test
    void confirmPasswordReset_shouldThrow_whenTokenInvalid() {
        when(userRepository.findByResetToken("invalid-token")).thenReturn(Optional.empty());

        assertThrows(InvalidTokenException.class,
                () -> authService.confirmPasswordReset(new PasswordResetConfirm("invalid-token", "SecureVault9$x")));
    }

    @Test
    void confirmPasswordReset_shouldThrow_whenResetTokenIsNull() {
        testUser.setResetToken(null);
        testUser.setResetTokenExpiresAt(LocalDateTime.now().plusMinutes(15));

        when(userRepository.findByResetToken(null)).thenReturn(Optional.empty());

        assertThrows(InvalidTokenException.class,
                () -> authService.confirmPasswordReset(new PasswordResetConfirm(null, "SecureVault9$x")));
    }
}
