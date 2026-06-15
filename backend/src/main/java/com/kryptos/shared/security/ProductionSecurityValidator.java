package com.kryptos.shared.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * ASVS V13.2.3 — Validates that no default/weak credentials are used in production.
 * Only active when the "prod" profile is enabled.
 */
@Component
@Profile("prod")
public class ProductionSecurityValidator {

    private static final Logger log = LoggerFactory.getLogger(ProductionSecurityValidator.class);

    private static final Set<String> FORBIDDEN_SECRETS = Set.of(
            "changeme", "changeme-use-a-strong-secret-in-production",
            "changeme-use-a-strong-256bit-secret-here",
            "changeme-use-a-strong-256bit-encryption-secret",
            "secret", "password", "admin", "root",
            "ci-dast-secret-minimum-256-bits-long-key-for-zap",
            "ci-dast-encryption-secret-256bits-long-value"
    );

    private static final Set<String> FORBIDDEN_DB_PASSWORDS = Set.of(
            "kryptos", "postgres", "password", "changeme",
            "admin", "root", "123456", ""
    );

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${kryptos.encryption.secret}")
    private String encryptionSecret;

    @Value("${spring.datasource.password}")
    private String dbPassword;

    @Value("${spring.datasource.username}")
    private String dbUsername;

    @EventListener(ApplicationReadyEvent.class)
    public void validateProductionSecrets() {
        List<String> violations = new ArrayList<>();

        if (FORBIDDEN_SECRETS.contains(jwtSecret.toLowerCase().trim())) {
            violations.add("jwt.secret uses a default/weak value");
        }
        if (jwtSecret.length() < 32) {
            violations.add("jwt.secret is shorter than 256 bits (32 bytes)");
        }

        if (FORBIDDEN_SECRETS.contains(encryptionSecret.toLowerCase().trim())) {
            violations.add("kryptos.encryption.secret uses a default/weak value");
        }
        if (encryptionSecret.length() < 32) {
            violations.add("kryptos.encryption.secret is shorter than 256 bits");
        }

        if (FORBIDDEN_DB_PASSWORDS.contains(dbPassword.toLowerCase().trim())) {
            violations.add("spring.datasource.password uses a default/weak value");
        }

        if ("root".equalsIgnoreCase(dbUsername) || "postgres".equalsIgnoreCase(dbUsername)
                || "admin".equalsIgnoreCase(dbUsername)) {
            violations.add("spring.datasource.username uses a privileged default account (" + dbUsername + ")");
        }

        if (!violations.isEmpty()) {
            String msg = "PRODUCTION SECURITY VIOLATIONS DETECTED:\n- "
                    + String.join("\n- ", violations);
            log.error(msg);
            throw new IllegalStateException(
                    "Application startup blocked: " + violations.size()
                            + " production security violation(s). See logs for details.");
        }

        log.info("Production security validation passed — no default credentials detected");
    }
}
