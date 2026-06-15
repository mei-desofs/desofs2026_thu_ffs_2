package com.kryptos.user.application;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.time.LocalDateTime;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.shared.security.JwtService;
import com.kryptos.user.application.dto.UpdateUserRequest;
import com.kryptos.user.application.dto.UserResponse;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final AuditService auditService;
    private final JwtService jwtService;

    public List<UserResponse> findAll() {
        return userRepository.findAll().stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    public UserResponse findById(UUID id, String currentUsername, boolean isAdmin) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!isAdmin && !user.getUsername().equals(currentUsername)) {
            throw new ForbiddenException("Access Denied: You can only view your own profile.");
        }

        return mapToResponse(user);
    }

    public void deleteById(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        String adminUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        String targetUsername = user.getUsername();

        user.setActive(false);
        user.setSessionTokenValidAfter(LocalDateTime.now());
        userRepository.save(user);

        auditService.log(AuditAction.USER_DELETE, adminUsername, "user",
                "Deactivated user: " + targetUsername + " (id: " + id + ")");
    }

    public UserResponse updateUserRole(UUID userId, Role newRole) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        String adminUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        user.setRole(newRole);
        userRepository.save(user);
        auditService.log(AuditAction.USER_ROLE_UPDATE, adminUsername, "user",
                "Updated role for user: " + user.getUsername() + " (id: " + userId + ") to " + newRole);
        return mapToResponse(user);
    }

    public UserResponse activateUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setActive(true);
        userRepository.save(user);
        return mapToResponse(user);
    }

    @Transactional
    public UserResponse update(UUID userId, UpdateUserRequest request, String currentUsername, boolean isAdmin) {
        jwtService.requireRecentAuthentication();
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!isAdmin && !user.getUsername().equals(currentUsername)) {
            throw new ForbiddenException("Unauthorized: You can only update your own profile");
        }

        if (request.email() != null && !request.email().isBlank()) {
            if (userRepository.existsByEmailAndIdNot(request.email(), userId)) {
                throw new IllegalArgumentException("Email already in use");
            }
            user.setEmail(request.email());
        }

        if (request.username() != null && !request.username().isBlank()) {
            user.setUsername(request.username());
        }

        auditService.log(AuditAction.USER_PROFILE_UPDATE, currentUsername, "user",
                String.format("Updated profile for user %s", userId));

        return mapToResponse(userRepository.save(user));
    }

    @Transactional
    public void terminateUserSessions(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        user.setSessionTokenValidAfter(LocalDateTime.now());
        userRepository.save(user);

        String adminUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.LOGOUT, adminUsername, "user",
                "Terminated all active sessions for user: " + user.getUsername());
    }

    @Transactional
    public void terminateAllSessions() {
        userRepository.terminateAllSessions(LocalDateTime.now());
        
        String adminUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.LOGOUT, adminUsername, "user",
                "Terminated all active sessions for ALL users globally (Panic Button)");
    }

    private UserResponse mapToResponse(User user) {
        return new UserResponse(
                user.getId(), 
                user.getUsername(), 
                user.getEmail(), 
                user.getRole()
        );
    }
}
