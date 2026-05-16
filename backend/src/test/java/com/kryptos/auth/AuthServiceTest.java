package com.kryptos.auth;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.kryptos.audit.application.AuditService;
import com.kryptos.auth.application.AuthService;
import com.kryptos.auth.application.dto.AuthResponse;
import com.kryptos.auth.application.dto.LoginRequest;
import com.kryptos.auth.application.dto.RegisterRequest;
import com.kryptos.shared.exception.RateLimitExceededException;
import com.kryptos.shared.security.JwtService;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private JwtService jwtService;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private AuditService auditService;

    @InjectMocks
    private AuthService authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("UserTest")
                .email("test@kryptos.com")
                .password("encoded_password")
                .role(Role.USER)
                .active(true)
                .build();
    }

    @Test
    void register_shouldReturnToken_whenValidRequest() {
        RegisterRequest request = new RegisterRequest("UserTest", "test@kryptos.com", "password123");
        
        when(userRepository.findByEmail(request.email())).thenReturn(Optional.empty());
        when(userRepository.findByUsername(request.username())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(request.password())).thenReturn("encoded_password");
        when(jwtService.generateToken(anyString(), anyString())).thenReturn("mock.jwt.token");

        AuthResponse response = authService.register(request);

        assertNotNull(response);
        assertEquals("mock.jwt.token", response.token());
        assertEquals("UserTest", response.username());
        assertEquals("USER", response.role());
        
        verify(userRepository).save(any(User.class));
    }

    @Test
    void register_shouldThrowException_whenUsernameOrEmailExists() {
        RegisterRequest request = new RegisterRequest("UserTest", "test@kryptos.com", "password123");
        when(userRepository.findByEmail(request.email())).thenReturn(Optional.of(testUser));

        assertThrows(IllegalArgumentException.class, () -> authService.register(request));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void login_shouldReturnToken_whenValidCredentials() {
        LoginRequest request = new LoginRequest("UserTest", "password123");
        
        when(userRepository.findByUsername(request.username())).thenReturn(Optional.of(testUser));
        when(jwtService.generateToken("UserTest", "USER")).thenReturn("mock.jwt.token");

        AuthResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("mock.jwt.token", response.token());
        
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtService).generateToken("UserTest", "USER");
    }

    @Test
    void login_shouldFail_whenWrongPassword() {
        LoginRequest request = new LoginRequest("UserTest", "wrongpassword");
        
        when(userRepository.findByUsername(request.username())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, 
                () -> authService.login(request));
                
        assertEquals("Invalid credentials", ex.getMessage());
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void login_shouldLockAccount_afterMaxFailedAttempts() {
        LoginRequest request = new LoginRequest("UserTest", "wrongpassword");
        
        when(userRepository.findByUsername(request.username())).thenReturn(Optional.of(testUser));
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        for (int i = 0; i < 5; i++) {
            assertThrows(IllegalArgumentException.class, () -> authService.login(request));
        }

        RateLimitExceededException ex = assertThrows(RateLimitExceededException.class, 
                () -> authService.login(request));
                
        assertTrue(ex.getMessage().contains("Too many failed attempts"));
    }
}