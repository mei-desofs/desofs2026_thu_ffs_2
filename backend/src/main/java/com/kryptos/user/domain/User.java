package com.kryptos.user.domain;

import jakarta.persistence.*;
import lombok.*;
import java.util.UUID;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Column(nullable = false)
    private boolean active;

    @Column(name = "reset_token")
    private String resetToken;

    @Column(name = "reset_token_expires_at")
    private LocalDateTime resetTokenExpiresAt;

    @Column(columnDefinition = "TEXT")
    private String passwordHistory;

    public List<String> getPasswordHistoryList() {
        if (passwordHistory == null || passwordHistory.isEmpty()) {
            return new ArrayList<>();
        }
        return List.of(passwordHistory.split(","));
    }

    public void addToPasswordHistory(String hashedPassword) {
        List<String> history = new ArrayList<>(getPasswordHistoryList());
        history.add(0, hashedPassword);
        if (history.size() > 3) {
            history = history.subList(0, 3);
        }
        this.passwordHistory = String.join(",", history);
    }
}
