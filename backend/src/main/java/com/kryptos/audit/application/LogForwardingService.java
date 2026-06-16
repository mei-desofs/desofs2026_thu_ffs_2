package com.kryptos.audit.application;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptos.audit.domain.AuditLog;
import com.kryptos.shared.security.OutboundConnectionValidator;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class LogForwardingService {

    private final String logForwardingUrl;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;
    private final OutboundConnectionValidator outboundValidator;

    public LogForwardingService(
            @Value("${kryptos.logging.forwarding.url:}") String logForwardingUrl,
            ObjectMapper objectMapper,
            OutboundConnectionValidator outboundValidator) {
        this.logForwardingUrl = logForwardingUrl;
        this.objectMapper = objectMapper;
        this.outboundValidator = outboundValidator;
        this.httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).build();
    }

    @Async
    public void forwardLog(AuditLog auditLog) {
        if (logForwardingUrl == null || logForwardingUrl.isBlank()) {
            log.debug("Log forwarding not configured, skipping");
            return;
        }

        try {
            outboundValidator.validateOutboundUrl(logForwardingUrl);
        } catch (SecurityException e) {
            log.error("Log forwarding blocked: {}", e.getMessage());
            return;
        }

        try {
            String jsonPayload = objectMapper.writeValueAsString(auditLog);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI(logForwardingUrl))
                    .header("Content-Type", "application/json")
                    .header("X-Forwarded-From", "kryptos-backend")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                    .timeout(java.time.Duration.ofSeconds(5))
                    .build();

            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                log.debug("Log forwarded successfully to {}", logForwardingUrl);
            } else {
                log.warn("Log forwarding failed with status {}: {}", response.statusCode(), response.body());
            }
        } catch (Exception e) {
            log.error("Failed to forward log to external system at {}: {}", logForwardingUrl, e.getMessage());
        }
    }
}
