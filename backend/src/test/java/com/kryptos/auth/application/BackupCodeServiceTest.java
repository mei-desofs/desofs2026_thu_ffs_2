package com.kryptos.auth.application;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.kryptos.user.domain.BackupCode;
import com.kryptos.user.domain.BackupCodeRepository;
import com.kryptos.user.domain.User;

@ExtendWith(MockitoExtension.class)
class BackupCodeServiceTest {

    @Mock
    private BackupCodeRepository backupCodeRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private BackupCodeService backupCodeService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@kryptos.com")
                .password("encoded_password")
                .build();
    }

    @Test
    void generateBackupCodes_shouldGenerate10Codes() {
        when(backupCodeRepository.saveAll(any())).thenReturn(List.of());

        List<String> codes = backupCodeService.generateBackupCodes(testUser);

        assertEquals(10, codes.size());
        codes.forEach(code -> {
            assertNotNull(code);
            assertTrue(code.matches("\\d{4}-\\d{4}"), "Code should be in format XXXX-XXXX");
        });
        verify(backupCodeRepository).saveAll(any());
    }

    @Test
    void generateBackupCodes_shouldEncodeAllCodesWithBcrypt() {
        when(passwordEncoder.encode(any())).thenReturn("encoded_hash");
        when(backupCodeRepository.saveAll(any())).thenReturn(List.of());

        backupCodeService.generateBackupCodes(testUser);

        verify(passwordEncoder, org.mockito.Mockito.times(10)).encode(any());
    }

    @Test
    void validateAndUseBackupCode_shouldReturnTrue_whenCodeMatches() {
        String plainCode = "1234-5678";
        BackupCode backupCode = BackupCode.builder()
                .user(testUser)
                .codeHash("hashed_code")
                .used(false)
                .build();

        when(backupCodeRepository.findByUserIdAndUsedFalse(testUser.getId()))
                .thenReturn(List.of(backupCode));
        when(passwordEncoder.matches(plainCode, "hashed_code")).thenReturn(true);
        when(backupCodeRepository.save(any())).thenReturn(backupCode);

        boolean result = backupCodeService.validateAndUseBackupCode(testUser, plainCode);

        assertTrue(result);
        assertTrue(backupCode.isUsed());
        verify(backupCodeRepository).save(backupCode);
    }

    @Test
    void validateAndUseBackupCode_shouldReturnFalse_whenCodeDoesNotMatch() {
        String plainCode = "1234-5678";
        BackupCode backupCode = BackupCode.builder()
                .user(testUser)
                .codeHash("hashed_code")
                .used(false)
                .build();

        when(backupCodeRepository.findByUserIdAndUsedFalse(testUser.getId()))
                .thenReturn(List.of(backupCode));
        when(passwordEncoder.matches(plainCode, "hashed_code")).thenReturn(false);

        boolean result = backupCodeService.validateAndUseBackupCode(testUser, plainCode);

        assertFalse(result);
        assertFalse(backupCode.isUsed());
    }

    @Test
    void validateAndUseBackupCode_shouldReturnFalse_whenNoUnusedCodes() {
        when(backupCodeRepository.findByUserIdAndUsedFalse(testUser.getId()))
                .thenReturn(List.of());

        boolean result = backupCodeService.validateAndUseBackupCode(testUser, "1234-5678");

        assertFalse(result);
    }

    @Test
    void getUnusedBackupCodeCount_shouldReturnCount() {
        BackupCode code1 = BackupCode.builder().used(false).build();
        BackupCode code2 = BackupCode.builder().used(false).build();

        when(backupCodeRepository.findByUserIdAndUsedFalse(testUser.getId()))
                .thenReturn(List.of(code1, code2));

        int count = backupCodeService.getUnusedBackupCodeCount(testUser);

        assertEquals(2, count);
    }
}
