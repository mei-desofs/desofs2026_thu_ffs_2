package com.kryptos.shared.security;

import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * ASVS V13.4.4 — Disable HTTP TRACE method.
 * ASVS V13.4.6 — Suppress server version headers.
 */
@Configuration
public class ServerHardeningConfig {

    /**
     * Customise embedded Tomcat to suppress the Server header
     * and disable the X-Powered-By header at connector level.
     */
    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> tomcatCustomizer() {
        return factory -> factory.addConnectorCustomizers(connector -> {
            connector.setProperty("server", "");
            connector.setXpoweredBy(false);
        });
    }

    /**
     * Servlet filter that:
     * - Blocks HTTP TRACE requests (V13.4.4)
     * - Strips version-revealing response headers (V13.4.6)
     */
    @Bean("traceAndHeaderFilter")
    public Filter traceAndHeaderFilter() {
        return new Filter() {
            @Override
            public void doFilter(ServletRequest request, ServletResponse response,
                                 FilterChain chain) throws IOException, ServletException {
                HttpServletRequest httpRequest = (HttpServletRequest) request;
                HttpServletResponse httpResponse = (HttpServletResponse) response;

                // V13.4.4 — Block TRACE method
                if ("TRACE".equalsIgnoreCase(httpRequest.getMethod())) {
                    httpResponse.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
                    return;
                }

                // V13.4.6 — Remove version-revealing headers
                httpResponse.setHeader("Server", "");
                httpResponse.setHeader("X-Powered-By", "");

                chain.doFilter(request, response);
            }
        };
    }
}
