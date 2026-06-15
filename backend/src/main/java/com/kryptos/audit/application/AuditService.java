package com.kryptos.audit.application;

import com.kryptos.audit.domain.AuditLog;
import com.kryptos.audit.domain.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final LogForwardingService logForwardingService;

    @Transactional
    public void log(String action, String performedBy, String targetResource, String details) {
        String sanitizedDetails = sanitize(details);
        LocalDateTime now = LocalDateTime.now();

        String previousHash = auditLogRepository.findFirstByOrderByTimestampDesc()
                .map(AuditLog::getHash)
                .orElse(null);

        String hash = computeHash(action, performedBy, targetResource, sanitizedDetails, now, previousHash);

        AuditLog entry = AuditLog.builder()
                .action(action)
                .performedBy(performedBy)
                .targetResource(targetResource)
                .details(sanitizedDetails)
                .timestamp(now)
                .hash(hash)
                .previousHash(previousHash)
                .build();

        AuditLog savedEntry = auditLogRepository.save(entry);

        logForwardingService.forwardLog(savedEntry);
    }

    private String computeHash(String action, String performedBy, String targetResource,
                                String details, LocalDateTime timestamp, String previousHash) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String input = String.join("\0",
                    nullToEmpty(action),
                    nullToEmpty(performedBy),
                    nullToEmpty(targetResource),
                    nullToEmpty(details),
                    nullToEmpty(previousHash),
                    timestamp != null ? timestamp.toString() : ""
            );
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private String sanitize(String input) {
        if (input == null) return null;
        return input.replaceAll("[\\x00-\\x1F\\x7F]", "");
    }

    private static String nullToEmpty(String s) {
        return s != null ? s : "";
    }
}
