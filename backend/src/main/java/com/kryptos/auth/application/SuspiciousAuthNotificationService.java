package com.kryptos.auth.application;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import com.kryptos.auth.application.dto.SuspiciousAuthAttempt;
import com.kryptos.shared.email.EmailService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SuspiciousAuthNotificationService {

    private final EmailService emailService;

    public void notifySuspiciousAttempt(SuspiciousAuthAttempt attempt) {
        String subject = "Suspicious authentication activity detected";
        String message = buildNotificationMessage(attempt);
        emailService.sendSuspiciousAuthNotification(attempt.email(), subject, message);
    }

    private String buildNotificationMessage(SuspiciousAuthAttempt attempt) {
        return String.format(
                "We detected suspicious authentication activity on your Kryptos account.\n\n" +
                "Reason: %s\n" +
                "Time: %s\n" +
                "IP Address: %s\n\n" +
                "If this was not you, please reset your password immediately.\n" +
                "For more information, visit: https://kryptos.com/security",
                attempt.reason(),
                attempt.attemptedAt(),
                attempt.ipAddress()
        );
    }
}
