package com.kryptos.shared.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final Optional<HmacAuthenticationFilter> hmacAuthenticationFilter;
    private final KryptosUserDetailsService userDetailsService;
    private final Environment environment;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/register", "/api/auth/login", "/api/auth/2fa/verify").permitAll()
                .requestMatchers("/api/auth/2fa/enable", "/api/auth/2fa/disable").authenticated()
                // V13.4.5 — Swagger/OpenAPI only accessible in non-prod profiles
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**")
                    .access((authentication, context) -> {
                        boolean isProd = Arrays.asList(environment.getActiveProfiles()).contains("prod");
                        return new org.springframework.security.authorization.AuthorizationDecision(!isProd);
                    })
                .anyRequest().authenticated()
            )
            .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(headers -> headers
                    .xssProtection(HeadersConfigurer.XXssConfig::disable)
                    .contentTypeOptions(HeadersConfigurer.ContentTypeOptionsConfig::disable)
                    .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                    .httpStrictTransportSecurity(hsts -> hsts
                            .includeSubDomains(true)
                            .maxAgeInSeconds(31536000))
                    .contentSecurityPolicy(csp -> csp
                            .policyDirectives("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'"))
            )
            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            )
            .authenticationProvider(authenticationProvider());
            
        hmacAuthenticationFilter.ifPresentOrElse(
            filter -> {
                http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
                http.addFilterAfter(jwtAuthFilter, HmacAuthenticationFilter.class);
            },
            () -> http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
        );

        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(); 
    }

    @Bean
    public HttpFirewall strictHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowedHttpMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        return firewall;
    }
}