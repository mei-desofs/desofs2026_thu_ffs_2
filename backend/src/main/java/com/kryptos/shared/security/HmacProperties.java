package com.kryptos.shared.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "kryptos.security.hmac")
public class HmacProperties {
    
    /**
     * The shared secret key used for HMAC-SHA256 signatures.
     * In a real production environment, this should be a strong, randomly generated key injected via environment variables.
     */
    private String secret = "super-secret-kryptos-hmac-key-change-in-production-1234567890";

    /**
     * Timestamp tolerance in seconds. Requests older than this will be rejected to prevent replay attacks.
     * Default is 300 seconds (5 minutes).
     */
    private long timestampToleranceSeconds = 300;
}
