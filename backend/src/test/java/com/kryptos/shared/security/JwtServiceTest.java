package com.kryptos.shared.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.kryptos.shared.exception.ReauthenticationRequiredException;
import com.kryptos.user.domain.User;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private static final String TEST_SECRET = "this-is-a-secret-that-is-at-least-32-bytes-long!!";
    private static final long TEST_EXPIRATION = 3600000; // 1 hour

    private JwtService jwtService;

    @Mock
    private RevokedTokenRepository revokedTokenRepository;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(revokedTokenRepository);
        ReflectionTestUtils.setField(jwtService, "secret", TEST_SECRET);
        ReflectionTestUtils.setField(jwtService, "expiration", TEST_EXPIRATION);
    }

    private KryptosUserDetails createMockUserDetails(String username) {
        if (username == null) return null;
        User user = new User();
        user.setUsername(username);
        user.setSessionTokenValidAfter(LocalDateTime.now().minusDays(1));
        return new KryptosUserDetails(user);
    }

    @Test
    void generateToken_shouldProduceValidToken() {
        String token = jwtService.generateToken("testuser", "USER");
        assertNotNull(token);
        assertFalse(token.isBlank());
        assertTrue(token.split("\\.").length == 3);
    }

    @Test
    void extractUsername_shouldReturnCorrectUsername() {
        String token = jwtService.generateToken("testuser", "USER");
        String extracted = jwtService.extractUsername(token);
        assertEquals("testuser", extracted);
    }

    @Test
    void isTokenValid_shouldReturnTrue_forValidToken() {
        String token = jwtService.generateToken("testuser", "USER");
        assertTrue(jwtService.isTokenValid(token, createMockUserDetails("testuser")));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forWrongUsername() {
        String token = jwtService.generateToken("testuser", "USER");
        assertFalse(jwtService.isTokenValid(token, createMockUserDetails("wronguser")));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forTamperedToken() {
        String token = jwtService.generateToken("testuser", "USER");
        String tampered = token.substring(0, token.lastIndexOf('.') + 1) + "tampered";
        assertFalse(jwtService.isTokenValid(tampered, createMockUserDetails("testuser")));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forGarbageToken() {
        assertFalse(jwtService.isTokenValid("not-a-jwt-token", createMockUserDetails("testuser")));
        assertFalse(jwtService.isTokenValid("", createMockUserDetails("testuser")));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forNullUsername() {
        String token = jwtService.generateToken("testuser", "USER");
        assertFalse(jwtService.isTokenValid(token, createMockUserDetails(null)));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forExpiredToken() {
        ReflectionTestUtils.setField(jwtService, "expiration", -1000L);
        String expiredToken = jwtService.generateToken("testuser", "USER");
        assertFalse(jwtService.isTokenValid(expiredToken, createMockUserDetails("testuser")));
    }

    @Test
    void constructor_shouldThrow_whenSecretIsTooShort() {
        JwtService shortSecretService = new JwtService(mock(RevokedTokenRepository.class));
        ReflectionTestUtils.setField(shortSecretService, "secret", "short");
        ReflectionTestUtils.setField(shortSecretService, "expiration", TEST_EXPIRATION);
        assertThrows(IllegalStateException.class,
                () -> shortSecretService.generateToken("user", "USER"));
    }

    @Test
    void extractIssuedAt_shouldReturnCorrectDate() {
        String token = jwtService.generateToken("testuser", "USER");
        Date issuedAt = jwtService.extractIssuedAt(token);
        assertNotNull(issuedAt);
    }

    @Test
    void requireRecentAuthentication_shouldPass_whenTokenRecent() {
        String token = jwtService.generateToken("testuser", "USER");
        Authentication auth = mock(Authentication.class);
        when(auth.getCredentials()).thenReturn(token);
        SecurityContext ctx = mock(SecurityContext.class);
        when(ctx.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(ctx);

        assertDoesNotThrow(() -> jwtService.requireRecentAuthentication());
    }

    @Test
    void requireRecentAuthentication_shouldThrow_whenTokenStale() {
        Date oldDate = Date.from(Instant.now().minusSeconds(400));
        String token = io.jsonwebtoken.Jwts.builder()
                .subject("testuser")
                .audience().add("kryptos").and()
                .issuedAt(oldDate)
                .expiration(new Date(oldDate.getTime() + TEST_EXPIRATION))
                .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(TEST_SECRET.getBytes(StandardCharsets.UTF_8)), io.jsonwebtoken.Jwts.SIG.HS256)
                .compact();

        Authentication auth = mock(Authentication.class);
        when(auth.getCredentials()).thenReturn(token);
        SecurityContext ctx = mock(SecurityContext.class);
        when(ctx.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(ctx);

        assertThrows(ReauthenticationRequiredException.class, 
            () -> jwtService.requireRecentAuthentication());
    }
}
