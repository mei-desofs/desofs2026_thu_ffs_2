package com.kryptos.auth.application;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kryptos.user.domain.BackupCode;
import com.kryptos.user.domain.BackupCodeRepository;
import com.kryptos.user.domain.User;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class BackupCodeService {

    private final BackupCodeRepository backupCodeRepository;
    private final PasswordEncoder passwordEncoder;
    private static final int BACKUP_CODES_COUNT = 10;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional
    public List<String> generateBackupCodes(User user) {
        List<String> plainCodes = new ArrayList<>();
        List<BackupCode> backupCodes = new ArrayList<>();

        for (int i = 0; i < BACKUP_CODES_COUNT; i++) {
            String plainCode = generateCode();
            plainCodes.add(plainCode);

            String codeHash = passwordEncoder.encode(plainCode);
            BackupCode backupCode = BackupCode.create(user, codeHash);
            backupCodes.add(backupCode);
        }

        backupCodeRepository.saveAll(backupCodes);
        return plainCodes;
    }

    @Transactional
    public boolean validateAndUseBackupCode(User user, String code) {
        List<BackupCode> unused = backupCodeRepository.findByUserIdAndUsedFalse(user.getId());

        for (BackupCode backupCode : unused) {
            if (passwordEncoder.matches(code, backupCode.getCodeHash())) {
                backupCode.setUsed(true);
                backupCodeRepository.save(backupCode);
                return true;
            }
        }

        return false;
    }

    public int getUnusedBackupCodeCount(User user) {
        return (int) backupCodeRepository.findByUserIdAndUsedFalse(user.getId()).stream()
                .filter(bc -> !bc.isUsed())
                .count();
    }

    private String generateCode() {
        StringBuilder code = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            int digit = SECURE_RANDOM.nextInt(10);
            code.append(digit);
            if (i == 3) {
                code.append("-");
            }
        }
        return code.toString();
    }
}
