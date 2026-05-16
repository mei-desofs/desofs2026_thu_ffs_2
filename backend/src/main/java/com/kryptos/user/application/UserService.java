package com.kryptos.user.application;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.shared.exception.ForbiddenException;
import com.kryptos.shared.exception.ResourceNotFoundException;
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
        userRepository.save(user);

        auditService.log(AuditAction.USER_DELETE, adminUsername, "user",
                "Deactivated user: " + targetUsername + " (id: " + id + ")");
    }

    public UserResponse updateUserRole(UUID userId, Role newRole) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        user.setRole(newRole);
        userRepository.save(user);
        return mapToResponse(user);
    }

    public UserResponse activateUser(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setActive(true);
        userRepository.save(user);
        return mapToResponse(user);
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
