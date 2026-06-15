package com.kryptos.credential.application;

import com.kryptos.credential.domain.Credential;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.shared.encryption.EncryptionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class CryptoMigrationService {

    private final CredentialRepository credentialRepository;
    private final EncryptionService encryptionService;

    /**
     * Re-encrypts all credentials in the database to use the current primary key and active encryption version (v2).
     * @return the number of credentials migrated
     */
    @Transactional
    public int migrateAllCredentials() {
        List<Credential> credentials = credentialRepository.findAll();
        int count = 0;

        for (Credential credential : credentials) {
            String currentEncrypted = credential.getEncryptedPassword();
            if (currentEncrypted == null || currentEncrypted.isBlank()) {
                continue;
            }

            try {
                // Decrypt using EncryptionService (which handles v1, v2, and previous secrets)
                String plaintext = encryptionService.decrypt(currentEncrypted);
                
                // Re-encrypt using the current primary key and version (v2$)
                String reEncrypted = encryptionService.encrypt(plaintext);

                // Check if it actually changed (if it was already v2$ with current key, it might still change due to random IV, 
                // but at least it ensures everything uses the latest KDF/Key).
                credential.setEncryptedPassword(reEncrypted);
                count++;
            } catch (Exception e) {
                log.error("Failed to migrate credential ID: {}", credential.getId(), e);
            }
        }
        
        // Save all changes (dirty checking works, but explicit saveAll is fine too)
        credentialRepository.saveAll(credentials);
        log.info("Successfully migrated {} credentials to the latest encryption standard.", count);
        return count;
    }
}
