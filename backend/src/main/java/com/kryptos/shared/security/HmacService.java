package com.kryptos.shared.security;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class HmacService {

    private static final String HMAC_ALGO = "HmacSHA256";
    private final HmacProperties hmacProperties;

    /**
     * Computes the HMAC-SHA256 signature for the given payload.
     * The payload format is: timestamp + HTTP_METHOD + URI + BODY
     */
    public String computeSignature(String timestamp, String method, String uri, String body) {
        try {
            String payload = timestamp + method + uri + (body != null ? body : "");
            
            Mac mac = Mac.getInstance(HMAC_ALGO);
            SecretKeySpec secretKey = new SecretKeySpec(hmacProperties.getSecret().getBytes(StandardCharsets.UTF_8), HMAC_ALGO);
            mac.init(secretKey);
            
            byte[] hmacBytes = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hmacBytes);
            
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to calculate HMAC signature", e);
        }
    }

    /**
     * Verifies if the provided signature matches the calculated signature.
     * Uses MessageDigest.isEqual for constant-time comparison to prevent timing attacks.
     */
    public boolean verifySignature(String providedSignature, String timestamp, String method, String uri, String body) {
        if (providedSignature == null || providedSignature.isEmpty()) {
            return false;
        }
        
        String expectedSignature = computeSignature(timestamp, method, uri, body);
        
        // Constant-time comparison
        return MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8), 
                providedSignature.getBytes(StandardCharsets.UTF_8)
        );
    }
    
    /**
     * Validates if the timestamp is within the acceptable tolerance window.
     */
    public boolean isValidTimestamp(String timestampHeader) {
        try {
            long timestamp = Long.parseLong(timestampHeader);
            long now = System.currentTimeMillis() / 1000; // current time in seconds
            long tolerance = hmacProperties.getTimestampToleranceSeconds();
            
            return Math.abs(now - timestamp) <= tolerance;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
