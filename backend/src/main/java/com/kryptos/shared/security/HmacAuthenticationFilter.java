package com.kryptos.shared.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@ConditionalOnProperty(name = "kryptos.security.hmac.enabled", havingValue = "true", matchIfMissing = true)
public class HmacAuthenticationFilter extends OncePerRequestFilter {

    private final HmacService hmacService;

    public HmacAuthenticationFilter(@Autowired(required = false) HmacService hmacService) {
        this.hmacService = hmacService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Bypass if HmacService is not loaded (e.g. in @WebMvcTest)
        if (hmacService == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Skip Swagger/OpenAPI and Actuator paths
        String path = request.getRequestURI();
        if (path.startsWith("/v3/api-docs") || path.startsWith("/swagger-ui") || path.startsWith("/actuator")) {
            filterChain.doFilter(request, response);
            return;
        }

        // For multipart requests, DO NOT wrap the request or read the InputStream.
        // Tomcat's getParts() requires the InputStream to be unread.
        String contentType = request.getContentType();
        boolean isMultipart = contentType != null && contentType.toLowerCase().startsWith("multipart/");

        HttpServletRequest requestToUse = request;
        String bodyForHmac = "";

        if (!isMultipart) {
            // Wrap the request to cache the body for JSON/plain text
            CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(request);
            requestToUse = cachedRequest;
            bodyForHmac = cachedRequest.getBodyAsString();
        }

        String timestamp = requestToUse.getHeader("X-Timestamp");
        String signature = requestToUse.getHeader("X-Signature");

        if (timestamp == null || signature == null) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("Missing required HMAC headers (X-Timestamp or X-Signature)");
            return;
        }

        if (!hmacService.isValidTimestamp(timestamp)) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("Timestamp expired or invalid. Possible replay attack.");
            return;
        }

        String method = requestToUse.getMethod();
        String uri = requestToUse.getRequestURI();
        if (requestToUse.getQueryString() != null) {
            uri += "?" + requestToUse.getQueryString();
        }

        if (!hmacService.verifySignature(signature, timestamp, method, uri, bodyForHmac)) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("Invalid HMAC signature. Message tampering detected.");
            return;
        }

        // Proceed with the wrapped request so other filters/controllers can read the body
        filterChain.doFilter(requestToUse, response);
    }
}
