package com.kryptos.auth;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.auth.application.AuthService;
import com.kryptos.auth.application.dto.PasswordResetConfirm;
import com.kryptos.shared.exception.InvalidTokenException;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

@ExtendWith(MockitoExtension.class)
class AccountLockoutIntegrationTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuditService auditService;

    @InjectMocks
    private AuthService authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@kryptos.com")
                .password("encoded_password")
                .role(Role.USER)
                .active(true)
                .accountLockedUntilAdmin(false)
                .build();
    }

    @Test
    void accountLockout_shouldLockAccount_afterThreeResetFailures() {
        String resetToken = UUID.randomUUID().toString();
        testUser.setResetToken(resetToken);
        testUser.setResetTokenExpiresAt(LocalDateTime.now().minusMinutes(1));

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.of(testUser));
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // Simulate 3 failed reset attempts with expired token
        for (int i = 0; i < 3; i++) {
            PasswordResetConfirm confirm = new PasswordResetConfirm(resetToken, "password123");
            assertThrows(InvalidTokenException.class, () -> authService.confirmPasswordReset(confirm));
        }

        // After 3 failures, account should be locked
        assertTrue(testUser.isAccountLockedUntilAdmin(),
                "Account should be locked after 3 reset failures");
        verify(auditService, atLeast(1)).log(eq(AuditAction.LOGIN_FAILED), eq("testuser"), eq("auth"),
                any());
    }

    @Test
    void resetFailure_shouldThrow_onExpiredToken() {
        String resetToken = UUID.randomUUID().toString();
        testUser.setResetToken(resetToken);
        testUser.setResetTokenExpiresAt(LocalDateTime.now().minusMinutes(1));

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.of(testUser));
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        PasswordResetConfirm confirm = new PasswordResetConfirm(resetToken, "password123");

        assertThrows(InvalidTokenException.class, () -> authService.confirmPasswordReset(confirm));
    }
}
