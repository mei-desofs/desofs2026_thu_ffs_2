package com.kryptos.shared.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HmacServiceTest {

    private HmacService hmacService;
    private HmacProperties properties;

    @BeforeEach
    void setUp() {
        properties = new HmacProperties();
        properties.setSecret("test-secret-key-12345");
        properties.setTimestampToleranceSeconds(300); // 5 minutes
        hmacService = new HmacService(properties);
    }

    @Test
    void testComputeAndVerifySignature() {
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000);
        String method = "POST";
        String uri = "/api/vaults";
        String body = "{\"name\":\"Test Vault\"}";

        // Compute signature
        String signature = hmacService.computeSignature(timestamp, method, uri, body);
        assertNotNull(signature);

        // Verify valid signature
        boolean isValid = hmacService.verifySignature(signature, timestamp, method, uri, body);
        assertTrue(isValid, "Signature should be valid for the exact same payload");

        // Verify invalid signature (tampered body)
        boolean isTamperedBodyValid = hmacService.verifySignature(signature, timestamp, method, uri, "{\"name\":\"Hacked Vault\"}");
        assertFalse(isTamperedBodyValid, "Signature should be invalid if body changes");

        // Verify invalid signature (tampered URI)
        boolean isTamperedUriValid = hmacService.verifySignature(signature, timestamp, method, "/api/vaults/123", body);
        assertFalse(isTamperedUriValid, "Signature should be invalid if URI changes");
    }

    @Test
    void testTimestampTolerance() {
        long now = System.currentTimeMillis() / 1000;
        
        // Valid (now)
        assertTrue(hmacService.isValidTimestamp(String.valueOf(now)));
        
        // Valid (4 minutes ago)
        assertTrue(hmacService.isValidTimestamp(String.valueOf(now - 240)));
        
        // Invalid (6 minutes ago)
        assertFalse(hmacService.isValidTimestamp(String.valueOf(now - 360)));
        
        // Invalid (future timestamp)
        assertFalse(hmacService.isValidTimestamp(String.valueOf(now + 360)));
    }
}
