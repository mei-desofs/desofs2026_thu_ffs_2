package com.kryptos.shared.email;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public void sendTwoFaCode(String toEmail, String code) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("Kryptos - Código de Verificação 2FA");
            message.setText(
                "O seu código de verificação é: " + code + "\n\n" +
                "Este código expira em 5 minutos.\n\n" +
                "Se não solicitou este código, ignore este email."
            );
            mailSender.send(message);
            log.info("2FA code sent to {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send 2FA email to {}: {}", toEmail, e.getMessage());
            throw new RuntimeException("Failed to send 2FA email");
        }
    }

    public void sendSuspiciousAuthNotification(String toEmail, String subject, String message) {
        try {
            SimpleMailMessage emailMessage = new SimpleMailMessage();
            emailMessage.setFrom(fromEmail);
            emailMessage.setTo(toEmail);
            emailMessage.setSubject(subject);
            emailMessage.setText(message);
            mailSender.send(emailMessage);
            log.info("Suspicious auth notification sent to {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send suspicious auth notification to {}: {}", toEmail, e.getMessage());
        }
    }
}
