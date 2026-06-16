package com.kryptos.shared.email;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.javamail.JavaMailSender;

import com.kryptos.shared.security.OutboundConnectionValidator;

@ExtendWith(MockitoExtension.class)
class EmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    @Mock
    private OutboundConnectionValidator outboundValidator;

    @Test
    void validateMailHost_shouldPass_whenMailHostIsAllowlisted() {
        doNothing().when(outboundValidator).validateOutboundHost("sandbox.smtp.mailtrap.io");

        EmailService service = new EmailService(mailSender, outboundValidator, "sandbox.smtp.mailtrap.io");
        service.setFromEmail("test@kryptos.com");

        assertDoesNotThrow(() -> service.validateMailHost());
        verify(outboundValidator).validateOutboundHost("sandbox.smtp.mailtrap.io");
    }

    @Test
    void validateMailHost_shouldThrow_whenMailHostNotAllowlisted() {
        doThrow(new SecurityException("Blocked")).when(outboundValidator).validateOutboundHost("evil-smtp.com");

        EmailService service = new EmailService(mailSender, outboundValidator, "evil-smtp.com");
        service.setFromEmail("test@kryptos.com");

        assertThrows(IllegalStateException.class, () -> service.validateMailHost());
        verify(outboundValidator).validateOutboundHost("evil-smtp.com");
    }

    @Test
    void constructor_shouldAcceptAllowlistedMailHost() {
        assertDoesNotThrow(() -> {
            EmailService service = new EmailService(mailSender, outboundValidator, "sandbox.smtp.mailtrap.io");
            service.setFromEmail("test@kryptos.com");
        });
    }
}
