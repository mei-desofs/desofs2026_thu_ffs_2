package com.kryptos.auth.application;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.kryptos.auth.application.dto.AuthResponse;
import com.kryptos.auth.application.dto.LoginRequest;
import com.kryptos.auth.application.dto.RegisterRequest;
import com.kryptos.shared.security.JwtService;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    private final ConcurrentHashMap<String, Integer> loginAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> lockouts = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.findByEmail(request.email()).isPresent() || 
            userRepository.findByUsername(request.username()).isPresent()) {
            throw new IllegalArgumentException("Username or Email already in use");
        }

        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password())) 
                .role(Role.USER) 
                .active(true) 
                .build();

        userRepository.save(user);
        
        String jwtToken = jwtService.generateToken(user.getUsername(), user.getRole().name());
        
        return new AuthResponse(jwtToken, user.getUsername(), user.getRole().name());
    }

    public AuthResponse login(LoginRequest request) {
        String cacheKey = request.username(); 

        if (lockouts.containsKey(cacheKey) && lockouts.get(cacheKey).isAfter(Instant.now())) {
            throw new RuntimeException("Too many failed attempts. Try again later."); 
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password()) 
            );

            loginAttempts.remove(cacheKey);
            lockouts.remove(cacheKey);

            // Fetching specifically by username since that's what the DTO provides
            var user = userRepository.findByUsername(request.username())
                    .orElseThrow();
                    
            String jwtToken = jwtService.generateToken(user.getUsername(), user.getRole().name());
            
            return new AuthResponse(jwtToken, user.getUsername(), user.getRole().name());

        } catch (Exception e) {
            int attempts = loginAttempts.getOrDefault(cacheKey, 0) + 1;
            loginAttempts.put(cacheKey, attempts);
            
            if (attempts >= MAX_ATTEMPTS) {
                lockouts.put(cacheKey, Instant.now().plusSeconds(900)); 
            }
            
            throw new IllegalArgumentException("Invalid credentials");
        }
    }
}