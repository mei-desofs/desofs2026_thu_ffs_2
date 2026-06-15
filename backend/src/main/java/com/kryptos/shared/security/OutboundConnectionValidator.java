package com.kryptos.shared.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Set;

/**
 * ASVS V13.2.4 — Allowlist of external resources the application may contact.
 * ASVS V13.2.5 — Allowlist of destinations for requests and file loading.
 *
 * Validates that any outbound connection attempt targets an allowed destination.
 * Prevents SSRF by blocking requests to internal/private networks and unapproved hosts.
 */
@Component
public class OutboundConnectionValidator {

    private static final Logger log = LoggerFactory.getLogger(OutboundConnectionValidator.class);

    @Value("${kryptos.security.allowed-external-hosts:sandbox.smtp.mailtrap.io}")
    private String allowedExternalHosts;

    /**
     * Validates that a URL targets an allowed external host and is not a private/internal address.
     *
     * @param url the URL to validate
     * @throws SecurityException if the URL is not allowed
     */
    public void validateOutboundUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new SecurityException("Outbound URL must not be null or blank");
        }

        try {
            URI uri = URI.create(url);
            String host = uri.getHost();

            if (host == null || host.isBlank()) {
                throw new SecurityException("Outbound URL has no host: " + url);
            }

            validateOutboundHost(host);

        } catch (IllegalArgumentException e) {
            throw new SecurityException("Invalid outbound URL: " + url, e);
        }
    }

    /**
     * Validates that a hostname targets an allowed external destination and is not
     * a private/internal address. Intended for non-HTTP outbound protocols such as SMTP.
     *
     * @param host the hostname to validate
     * @throws SecurityException if the host is not allowed
     */
    public void validateOutboundHost(String host) {
        if (host == null || host.isBlank()) {
            throw new SecurityException("Outbound host must not be null or blank");
        }

        // Block private/internal IP ranges (SSRF protection)
        validateNotPrivateAddress(host);

        // Check against allowlist
        Set<String> allowed = Set.of(allowedExternalHosts.split(","));
        if (!allowed.contains(host.toLowerCase())) {
            log.warn("Blocked outbound connection to non-allowlisted host: {}", host);
            throw new SecurityException(
                    "Outbound connection to host '" + host + "' is not in the allowlist");
        }
    }

    private void validateNotPrivateAddress(String host) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()
                        || addr.isLinkLocalAddress() || addr.isAnyLocalAddress()
                        || isPrivateRange(addr)) {
                    log.warn("Blocked SSRF attempt to private/internal address: {} -> {}", host, addr);
                    throw new SecurityException(
                            "Outbound connection to private/internal address is forbidden: " + host);
                }
            }
        } catch (UnknownHostException e) {
            throw new SecurityException("Cannot resolve outbound host: " + host, e);
        }
    }

    private boolean isPrivateRange(InetAddress addr) {
        byte[] bytes = addr.getAddress();
        if (bytes.length == 4) {
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            if (first == 10) return true;
            if (first == 172 && second >= 16 && second <= 31) return true;
            if (first == 192 && second == 168) return true;
            if (first == 169 && second == 254) return true;
        }
        return false;
    }
}
