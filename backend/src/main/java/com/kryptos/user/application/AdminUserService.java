package com.kryptos.user.application;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.user.application.dto.AdminPasswordResetResponse;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AdminUserService {

    private final UserRepository userRepository;
    private final AuditService auditService;

    @Transactional
    public AdminPasswordResetResponse initiatePasswordReset(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        String resetToken = UUID.randomUUID().toString();
        user.setResetToken(resetToken);
        user.setResetTokenExpiresAt(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        auditService.log(AuditAction.PASSWORD_RESET_REQUESTED, user.getUsername(), "admin",
                "Admin initiated password reset for user: " + user.getUsername());

        return new AdminPasswordResetResponse(
                user.getId(),
                user.getUsername(),
                "Password reset initiated. User can reset password using the provided token.",
                resetToken
        );
    }
}
