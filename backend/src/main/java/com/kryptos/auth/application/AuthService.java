package com.kryptos.auth.application;

import com.kryptos.auth.application.dto.AuthResponse;
import com.kryptos.auth.application.dto.LoginRequest;
import com.kryptos.auth.application.dto.RegisterRequest;
import com.kryptos.user.domain.UserRepository;
import com.kryptos.shared.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public AuthResponse register(RegisterRequest request) {
        // TODO
        return null;
    }

    public AuthResponse login(LoginRequest request) {
        // TODO
        return null;
    }
}
