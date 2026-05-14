package com.kryptos.user.application;

import com.kryptos.user.application.dto.UserResponse;
import com.kryptos.user.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public List<UserResponse> findAll() {
        // TODO
        return List.of();
    }

    public UserResponse findById(UUID id) {
        // TODO
        return null;
    }

    public void deleteById(UUID id) {
        // TODO
    }
}
