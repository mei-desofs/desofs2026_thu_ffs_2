package com.kryptos.user.domain;

import java.util.UUID;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "backup_codes")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BackupCode {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    private String codeHash;
    private boolean used;

    public static BackupCode create(User user, String codeHash) {
        return BackupCode.builder()
                .user(user)
                .codeHash(codeHash)
                .used(false)
                .build();
    }
}
