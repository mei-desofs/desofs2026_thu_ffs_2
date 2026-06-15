package com.kryptos.shared.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.IOException;
import java.util.Set;

/**
 * ASVS V13.4.3 — No directory listings exposed.
 * ASVS V13.4.7 — Only serve files with specific allowed extensions.
 *
 * Since Kryptos is a REST API (no static web tier), this config ensures:
 * - No static resource serving by default
 * - A filter blocks requests for sensitive file extensions
 */
@Configuration
public class StaticResourceSecurityConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Do not register any static resource handlers.
        // Kryptos is a pure REST API — no static files should be served.
    }

    /**
     * Block requests for files with sensitive extensions that should never be
     * served: configuration files, backups, source control metadata, etc.
     */
    @Bean
    public Filter sensitiveFileExtensionFilter() {
        Set<String> blocked = Set.of(
                ".properties", ".yml", ".yaml", ".xml", ".env",
                ".bak", ".old", ".orig", ".swp", ".tmp",
                ".git", ".svn", ".hg",
                ".java", ".class", ".jar",
                ".log", ".sql", ".sh", ".bat",
                ".key", ".pem", ".crt", ".p12", ".jks"
        );

        return new Filter() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response,
                                 FilterChain chain) throws IOException, ServletException {
                HttpServletRequest httpReq = (HttpServletRequest) request;
                String path = httpReq.getRequestURI().toLowerCase();

                for (String ext : blocked) {
                    if (path.endsWith(ext)) {
                        ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_NOT_FOUND);
                        return;
                    }
                }

                chain.doFilter(request, response);
            }
        };
    }
}
