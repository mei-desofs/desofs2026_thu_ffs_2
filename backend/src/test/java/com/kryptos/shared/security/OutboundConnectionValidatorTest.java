package com.kryptos.shared.security;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class OutboundConnectionValidatorTest {

    private OutboundConnectionValidator validator;

    @BeforeEach
    void setUp() {
        validator = new OutboundConnectionValidator();
        ReflectionTestUtils.setField(validator, "allowedExternalHosts",
                "sandbox.smtp.mailtrap.io,8.8.8.8,api.trusted.com");
    }

    @Test
    void validateOutboundUrl_shouldAcceptAllowlistedUrl() {
        assertDoesNotThrow(() ->
                validator.validateOutboundUrl("http://8.8.8.8/api/logs"));
    }

    @Test
    void validateOutboundUrl_shouldRejectNonAllowlistedUrl() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundUrl("https://evil.com/exfiltrate"));
    }

    @Test
    void validateOutboundUrl_shouldRejectNullUrl() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundUrl(null));
    }

    @Test
    void validateOutboundUrl_shouldRejectBlankUrl() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundUrl("  "));
    }

    @Test
    void validateOutboundUrl_shouldRejectUrlWithoutHost() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundUrl("not-a-valid-url"));
    }

    @Test
    void validateOutboundUrl_shouldRejectPrivateIp() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundUrl("http://192.168.1.1/steal"));
    }

    @Test
    void validateOutboundUrl_shouldRejectLoopback() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundUrl("http://127.0.0.1/steal"));
    }

    @Test
    void validateOutboundHost_shouldAcceptAllowlistedHost() {
        assertDoesNotThrow(() ->
                validator.validateOutboundHost("8.8.8.8"));
    }

    @Test
    void validateOutboundHost_shouldRejectNonAllowlistedHost() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundHost("evil-tracker.com"));
    }

    @Test
    void validateOutboundHost_shouldRejectNullHost() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundHost(null));
    }

    @Test
    void validateOutboundHost_shouldRejectBlankHost() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundHost("  "));
    }

    @Test
    void validateOutboundHost_shouldRejectPrivateIp() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundHost("10.0.0.1"));
    }

    @Test
    void validateOutboundHost_shouldRejectLoopback() {
        assertThrows(SecurityException.class, () ->
                validator.validateOutboundHost("127.0.0.1"));
    }
}
