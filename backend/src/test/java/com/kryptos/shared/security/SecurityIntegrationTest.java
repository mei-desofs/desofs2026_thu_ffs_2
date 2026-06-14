package com.kryptos.shared.security;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.auth.application.AuthService;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@ExtendWith(MockitoExtension.class)
class SecurityIntegrationTest {

    private static final String TEST_SECRET = "this-is-a-secret-that-is-at-least-32-bytes-long!!";
    private static final long TEST_EXPIRATION = 3600000;

    private JwtService jwtService;
    private RevokedTokenRepository revokedTokenRepository;
    private KryptosUserDetailsService userDetailsService;

    @Mock private UserRepository userRepository;
    @Mock private AuditService auditService;
    @InjectMocks private AuthService authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(revokedTokenRepository);
        revokedTokenRepository = mock(RevokedTokenRepository.class);
        ReflectionTestUtils.setField(jwtService, "secret", TEST_SECRET);
        ReflectionTestUtils.setField(jwtService, "expiration", TEST_EXPIRATION);
        ReflectionTestUtils.setField(jwtService, "revokedTokenRepository", revokedTokenRepository);

        userDetailsService = new KryptosUserDetailsService(userRepository);
        ReflectionTestUtils.setField(authService, "jwtService", jwtService);

        SecurityContextHolder.clearContext();

        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@kryptos.com")
                .password("hashedpassword")
                .role(Role.USER)
                .active(true)
                .build();
    }

    @Test
    void revokeToken_shouldPersistRevokedToken() {
        String token = jwtService.generateToken("testuser", "USER");

        jwtService.revokeToken(token);

        ArgumentCaptor<RevokedToken> captor = ArgumentCaptor.forClass(RevokedToken.class);
        verify(revokedTokenRepository).save(captor.capture());
        RevokedToken saved = captor.getValue();
        assertNotNull(saved.getTokenHash());
        assertNotNull(saved.getRevokedAt());
        assertNotNull(saved.getExpiresAt());
    }

    @Test
    void revokeToken_shouldThrow_whenTokenMalformed() {
        assertThrows(RuntimeException.class,
                () -> jwtService.revokeToken("malformed-token"));
    }

    @Test
    void revokeToken_shouldNotThrow_whenCalledTwice() {
        String token = jwtService.generateToken("testuser", "USER");

        jwtService.revokeToken(token);
        jwtService.revokeToken(token);

        verify(revokedTokenRepository, times(2)).save(any(RevokedToken.class));
    }

    @Test
    void isTokenRevoked_shouldReturnTrue_whenTokenInBlacklist() {
        String token = jwtService.generateToken("testuser", "USER");
        when(revokedTokenRepository.existsByTokenHashAndExpiresAtAfter(anyString(), any(LocalDateTime.class)))
                .thenReturn(true);

        assertTrue(jwtService.isTokenRevoked(token));
    }

    @Test
    void isTokenRevoked_shouldReturnFalse_whenTokenNotInBlacklist() {
        String token = jwtService.generateToken("testuser", "USER");
        when(revokedTokenRepository.existsByTokenHashAndExpiresAtAfter(anyString(), any(LocalDateTime.class)))
                .thenReturn(false);

        assertFalse(jwtService.isTokenRevoked(token));
    }

    @Test
    void isTokenRevoked_shouldReturnFalse_whenTokenMalformed() {
        assertFalse(jwtService.isTokenRevoked("clearly-malformed"));
    }

    @Test
    void isTokenRevoked_shouldUseTokenHash_forLookup() {
        String token = jwtService.generateToken("testuser", "USER");
        when(revokedTokenRepository.existsByTokenHashAndExpiresAtAfter(anyString(), any(LocalDateTime.class)))
                .thenReturn(false);

        jwtService.isTokenRevoked(token);

        verify(revokedTokenRepository).existsByTokenHashAndExpiresAtAfter(anyString(), any(LocalDateTime.class));
    }

    @Test
    void hashToken_shouldProduce64CharHexString() {
        String token = jwtService.generateToken("testuser", "USER");
        String hash = ReflectionTestUtils.invokeMethod(jwtService, "hashToken", token);
        assertNotNull(hash);
        assertEquals(64, hash.length());
    }

    @Test
    void hashToken_shouldBeDeterministic() {
        String token = jwtService.generateToken("testuser", "USER");
        String hash1 = ReflectionTestUtils.invokeMethod(jwtService, "hashToken", token);
        String hash2 = ReflectionTestUtils.invokeMethod(jwtService, "hashToken", token);
        assertEquals(hash1, hash2);
    }

    @Test
    void hashToken_shouldDiffer_forDifferentTokens() {
        String token1 = jwtService.generateToken("user1", "USER");
        String token2 = jwtService.generateToken("user2", "USER");
        String hash1 = ReflectionTestUtils.invokeMethod(jwtService, "hashToken", token1);
        String hash2 = ReflectionTestUtils.invokeMethod(jwtService, "hashToken", token2);
        assertNotEquals(hash1, hash2);
    }

    @Test
    void revokedToken_shouldBeRejected_afterLogout() {
        String token = jwtService.generateToken("testuser", "USER");

        jwtService.revokeToken(token);

        when(revokedTokenRepository.existsByTokenHashAndExpiresAtAfter(anyString(), any(LocalDateTime.class)))
                .thenReturn(true);

        assertTrue(jwtService.isTokenRevoked(token));
    }

    @Test
    void isTokenValid_shouldReturnFalse_whenTokenExpired() {
        ReflectionTestUtils.setField(jwtService, "expiration", -1000L);
        String expiredToken = jwtService.generateToken("testuser", "USER");

        assertFalse(jwtService.isTokenValid(expiredToken, "testuser"));
    }

    @Test
    void expiredToken_shouldNotBeRevocable() {
        ReflectionTestUtils.setField(jwtService, "expiration", -1000L);
        String expiredToken = jwtService.generateToken("testuser", "USER");

        assertThrows(RuntimeException.class,
                () -> jwtService.revokeToken(expiredToken));
    }

    @Test
    void authServiceLogout_shouldAudit() {
        String token = jwtService.generateToken("testuser", "USER");

        authService.logout(token, "testuser");

        verify(auditService).log(eq(AuditAction.LOGOUT), eq("testuser"), eq("auth"), anyString());
    }

    @Test
    void fullLogoutFlow_shouldRevokeTokenAndAudit() {
        String token = jwtService.generateToken("testuser", "USER");

        authService.logout(token, "testuser");

        verify(revokedTokenRepository).save(any(RevokedToken.class));
        verify(auditService).log(eq(AuditAction.LOGOUT), eq("testuser"), eq("auth"), anyString());
    }

    @Test
    void filter_shouldContinueChain_whenTokenRevoked() throws Exception {
        String token = jwtService.generateToken("testuser", "USER");
        when(revokedTokenRepository.existsByTokenHashAndExpiresAtAfter(anyString(), any(LocalDateTime.class)))
                .thenReturn(true);

        JwtAuthFilter filter = new JwtAuthFilter(jwtService, userDetailsService);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void filter_shouldContinueChain_whenTokenValid() throws Exception {
        String token = jwtService.generateToken("testuser", "USER");
        when(revokedTokenRepository.existsByTokenHashAndExpiresAtAfter(anyString(), any(LocalDateTime.class)))
                .thenReturn(false);
        when(userRepository.findByUsername("testuser")).thenReturn(java.util.Optional.of(testUser));

        JwtAuthFilter filter = new JwtAuthFilter(jwtService, userDetailsService);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void filter_shouldContinueChain_whenNoAuthHeader() throws Exception {
        JwtAuthFilter filter = new JwtAuthFilter(jwtService, userDetailsService);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        when(request.getHeader("Authorization")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(revokedTokenRepository);
    }

    @Test
    void filter_shouldContinueChain_whenBearerTokenEmpty() throws Exception {
        JwtAuthFilter filter = new JwtAuthFilter(jwtService, userDetailsService);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        when(request.getHeader("Authorization")).thenReturn("Bearer ");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(revokedTokenRepository);
    }

    @Test
    void filter_shouldContinueChain_whenTokenInvalid() throws Exception {
        JwtAuthFilter filter = new JwtAuthFilter(jwtService, userDetailsService);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        when(request.getHeader("Authorization")).thenReturn("Bearer invalid.token.here");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void filter_shouldNotCheckRevocation_whenNoBearerToken() throws Exception {
        JwtAuthFilter filter = new JwtAuthFilter(jwtService, userDetailsService);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        when(request.getHeader("Authorization")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(revokedTokenRepository, never()).existsByTokenHashAndExpiresAtAfter(anyString(), any());
    }
}