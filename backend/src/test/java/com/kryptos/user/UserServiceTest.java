package com.kryptos.user;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.user.application.UserService;
import com.kryptos.user.application.dto.UserResponse;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private AuditService auditService; // 1. Adicionado o mock do AuditService

    @InjectMocks
    private UserService userService;

    private User targetUser;
    private UUID targetUserId;

    @BeforeEach
    void setUp() {
        targetUserId = UUID.randomUUID();
        targetUser = User.builder()
                .id(targetUserId)
                .username("targetuser")
                .email("target@kryptos.com")
                .role(Role.USER)
                .active(true)
                .build();

        Authentication auth = mock(Authentication.class);
        lenient().when(auth.getName()).thenReturn("admin_user");
        SecurityContext ctx = mock(SecurityContext.class);
        lenient().when(ctx.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(ctx);
    }

    @Test
    void findById_shouldReturnUser_whenUserRequestsOwnProfile() {
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));

        UserResponse response = userService.findById(targetUserId, "targetuser", false);

        assertNotNull(response);
        assertEquals(targetUserId, response.id());
        assertEquals("targetuser", response.username());
    }

    @Test
    void findById_shouldThrowForbidden_whenUserRequestsOtherProfile() {
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));

        assertThrows(ForbiddenException.class, 
                () -> userService.findById(targetUserId, "hacker_user", false));
    }

    @Test
    void findById_shouldReturnUser_whenAdminRequestsOtherProfile() {
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));

        UserResponse response = userService.findById(targetUserId, "admin_user", true);

        assertNotNull(response);
        assertEquals("targetuser", response.username());
    }

    @Test
    void deleteById_shouldSoftDeleteUser() {
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));

        userService.deleteById(targetUserId);

        assertFalse(targetUser.isActive());
        verify(userRepository).save(targetUser);
        verify(userRepository, never()).delete(any());
        
        verify(auditService).log(any(), eq("admin_user"), any(), any());
    }

    @Test
    void updateUserRole_shouldChangeRoleAndSave() {
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));

        UserResponse response = userService.updateUserRole(targetUserId, Role.ADMIN);

        assertEquals(Role.ADMIN, targetUser.getRole());
        assertEquals(Role.ADMIN, response.role());
        verify(userRepository).save(targetUser);
        verify(auditService).log(eq(AuditAction.USER_ROLE_UPDATE), eq("admin_user"), eq("user"), any());
    }
}