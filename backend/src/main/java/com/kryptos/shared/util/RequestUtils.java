package com.kryptos.shared.util;

import jakarta.servlet.http.HttpServletRequest;

public class RequestUtils {

    private RequestUtils() {
        // Utility class
    }

    public static String extractClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public static String extractUserAgent(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        return (ua != null && !ua.isEmpty()) ? ua : "Unknown";
    }
}
