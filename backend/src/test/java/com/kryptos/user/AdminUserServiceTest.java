package com.kryptos.user;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.user.application.AdminUserService;
import com.kryptos.user.application.dto.AdminPasswordResetResponse;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

@ExtendWith(MockitoExtension.class)
class AdminUserServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private AuditService auditService;

    @InjectMocks
    private AdminUserService adminUserService;

    private User testUser;
    private UUID userId;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        testUser = User.builder()
                .id(userId)
                .username("testuser")
                .email("test@kryptos.com")
                .password("encoded_password")
                .role(Role.USER)
                .active(true)
                .build();
    }

    @Test
    void initiatePasswordReset_shouldGenerateToken_whenUserExists() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any())).thenReturn(testUser);

        AdminPasswordResetResponse response = adminUserService.initiatePasswordReset(userId);

        assertNotNull(response);
        assertEquals(userId, response.userId());
        assertEquals("testuser", response.username());
        assertNotNull(response.resetToken());

        verify(userRepository).save(testUser);
        verify(auditService).log(eq(AuditAction.PASSWORD_RESET_REQUESTED), eq("testuser"), eq("admin"), any());
    }

    @Test
    void initiatePasswordReset_shouldThrow_whenUserNotFound() {
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class,
                () -> adminUserService.initiatePasswordReset(userId));
    }

    @Test
    void initiatePasswordReset_shouldSetResetTokenExpiration() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        when(userRepository.save(any())).thenReturn(testUser);

        adminUserService.initiatePasswordReset(userId);

        assertNotNull(testUser.getResetToken());
        assertNotNull(testUser.getResetTokenExpiresAt());
    }
}
