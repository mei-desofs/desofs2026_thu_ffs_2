package com.kryptos.auth.application;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import com.kryptos.auth.application.dto.SuspiciousAuthAttempt;
import com.kryptos.user.domain.User;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthExpiryNotificationService {

    private final SuspiciousAuthNotificationService suspiciousAuthNotificationService;
    private static final int DAYS_BEFORE_EXPIRY_THRESHOLD = 1;

    public void checkAndNotifyExpiringAuthMethods(User user) {
        checkTwoFaExpiry(user);
        checkPasswordResetExpiry(user);
    }

    private void checkTwoFaExpiry(User user) {
        if (user.isTwoFaEnabled() && user.getTwoFaCodeExpiresAt() != null) {
            LocalDateTime expiryTime = user.getTwoFaCodeExpiresAt();
            LocalDateTime thresholdTime = LocalDateTime.now().plusDays(DAYS_BEFORE_EXPIRY_THRESHOLD);

            if (expiryTime.isBefore(thresholdTime) && expiryTime.isAfter(LocalDateTime.now())) {
                notifyAuthExpiryApproaching(user, "Two-factor authentication code will expire soon. Please renew it to maintain account security.");
            }
        }
    }

    private void checkPasswordResetExpiry(User user) {
        if (user.getResetTokenExpiresAt() != null) {
            LocalDateTime expiryTime = user.getResetTokenExpiresAt();
            LocalDateTime thresholdTime = LocalDateTime.now().plusDays(DAYS_BEFORE_EXPIRY_THRESHOLD);

            if (expiryTime.isBefore(thresholdTime) && expiryTime.isAfter(LocalDateTime.now())) {
                notifyAuthExpiryApproaching(user, "Your password reset token will expire soon. Complete the reset process to secure your account.");
            }
        }
    }

    private void notifyAuthExpiryApproaching(User user, String message) {
        suspiciousAuthNotificationService.notifySuspiciousAttempt(
            new SuspiciousAuthAttempt(
                user.getUsername(),
                user.getEmail(),
                message,
                "renewal-check",
                "scheduled",
                LocalDateTime.now()
            )
        );
    }
}
