package com.kryptos.auth;

import com.kryptos.auth.application.AuthService;
import com.kryptos.audit.application.AuditService;
import com.kryptos.user.domain.UserRepository;
import com.kryptos.shared.security.JwtService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private AuthService authService;

    @Test
    void register_shouldReturnToken_whenValidRequest() {
        // TODO
    }

    @Test
    void login_shouldReturnToken_whenValidCredentials() {
        // TODO
    }

    @Test
    void login_shouldFail_whenWrongPassword() {
        // TODO
    }
}
