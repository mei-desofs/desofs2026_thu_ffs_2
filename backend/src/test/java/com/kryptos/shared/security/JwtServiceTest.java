package com.kryptos.shared.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private static final String TEST_SECRET = "this-is-a-secret-that-is-at-least-32-bytes-long!!";
    private static final long TEST_EXPIRATION = 3600000; // 1 hour

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secret", TEST_SECRET);
        ReflectionTestUtils.setField(jwtService, "expiration", TEST_EXPIRATION);
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
        assertTrue(jwtService.isTokenValid(token, "testuser"));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forWrongUsername() {
        String token = jwtService.generateToken("testuser", "USER");
        assertFalse(jwtService.isTokenValid(token, "wronguser"));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forTamperedToken() {
        String token = jwtService.generateToken("testuser", "USER");
        String tampered = token.substring(0, token.lastIndexOf('.') + 1) + "tampered";
        assertFalse(jwtService.isTokenValid(tampered, "testuser"));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forGarbageToken() {
        assertFalse(jwtService.isTokenValid("not-a-jwt-token", "testuser"));
        assertFalse(jwtService.isTokenValid("", "testuser"));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forNullUsername() {
        String token = jwtService.generateToken("testuser", "USER");
        assertFalse(jwtService.isTokenValid(token, null));
    }

    @Test
    void isTokenValid_shouldReturnFalse_forExpiredToken() {
        ReflectionTestUtils.setField(jwtService, "expiration", -1000L);
        String expiredToken = jwtService.generateToken("testuser", "USER");
        assertFalse(jwtService.isTokenValid(expiredToken, "testuser"));
    }

    @Test
    void constructor_shouldThrow_whenSecretIsTooShort() {
        JwtService shortSecretService = new JwtService();
        ReflectionTestUtils.setField(shortSecretService, "secret", "short");
        ReflectionTestUtils.setField(shortSecretService, "expiration", TEST_EXPIRATION);
        assertThrows(IllegalStateException.class,
                () -> shortSecretService.generateToken("user", "USER"));
    }
}
