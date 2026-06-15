package com.kryptos.filehandling.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptos.credential.domain.Credential;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.filehandling.application.dto.CredentialExportRecord;
import com.kryptos.shared.encryption.EncryptionService;
import com.kryptos.shared.exception.EncryptionException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;
import com.kryptos.vault.domain.Vault;
import com.kryptos.vault.domain.VaultRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


@Service
@RequiredArgsConstructor
public class CredentialImportExportService {

    private static final String DEFAULT_IMPORTED_VAULT = "Imported";

    private final CredentialRepository credentialRepository;
    private final VaultRepository vaultRepository;
    private final UserRepository userRepository;
    private final EncryptionService encryptionService;
    private final FileHandlingService fileHandlingService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Transactional(readOnly = true)
    public byte[] exportForOwner(UUID ownerId) throws IOException {
        User owner = userRepository.findById(ownerId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        List<String> encryptedRecords = new ArrayList<>();
        for (Vault vault : vaultRepository.findAllByOwnerId(ownerId)) {
            for (Credential credential : credentialRepository.findAllByVaultId(vault.getId())) {
                CredentialExportRecord record = new CredentialExportRecord(
                        credential.getServiceName(),
                        credential.getUsername(),
                        encryptionService.decrypt(credential.getEncryptedPassword()),
                        credential.getUrl(),
                        credential.getNotes(),
                        vault.getName());
                try {
                    encryptedRecords.add(encryptionService.encrypt(
                            objectMapper.writeValueAsString(record)));
                } catch (JsonProcessingException e) {
                    throw new IOException("Failed to serialise credential for export", e);
                }
            }
        }

        Path exportFile = fileHandlingService.exportCredentials(
                encryptedRecords, "kryptos-export-" + owner.getUsername() + ".kvault");
        try {
            return Files.readAllBytes(exportFile);
        } finally {
            safeSecureDelete(exportFile);
        }
    }

    @Transactional
    public int importForOwner(byte[] uploadedBytes, String originalFilename, UUID ownerId)
            throws IOException {
        return importForOwner(uploadedBytes, originalFilename, ownerId, false);
    }

    @Transactional
    public int importForOwner(byte[] uploadedBytes, String originalFilename, UUID ownerId, boolean consentToStorage)
            throws IOException {
        if (uploadedBytes == null || uploadedBytes.length == 0) {
            throw new IllegalArgumentException("Import file is empty");
        }
        User owner = userRepository.findById(ownerId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Path stored = fileHandlingService.storeUpload(uploadedBytes, originalFilename, !consentToStorage);
        try {
            List<String> records = fileHandlingService.importCredentials(stored);

            int imported = 0;
            for (String line : records) {
                CredentialExportRecord record;
                try {
                    record = objectMapper.readValue(
                            encryptionService.decrypt(line), CredentialExportRecord.class);
                } catch (EncryptionException | JsonProcessingException skipBadLine) {
                    continue;
                }
                if (record == null || isBlank(record.serviceName())
                        || isBlank(record.username()) || record.password() == null) {
                    continue;
                }

                Vault vault = resolveImportVault(owner, record.vaultName());
                credentialRepository.save(Credential.builder()
                        .serviceName(safe(record.serviceName(), 100))
                        .username(safe(record.username(), 100))
                        .encryptedPassword(encryptionService.encrypt(record.password()))
                        .url(safe(record.url(), 500))
                        .notes(safe(record.notes(), 2000))
                        .vault(vault)
                        .build());
                imported++;
            }
            return imported;
        } finally {
            safeSecureDelete(stored);
            // Best-effort: zero the in-memory plaintext buffer.
            java.util.Arrays.fill(uploadedBytes, (byte) 0);
        }
    }

    private void safeSecureDelete(Path path) throws IOException {
        try {
            fileHandlingService.secureDelete(path);
        } catch (IllegalArgumentException ignoreInternalMisuse) {
            // Should not happen — we only pass paths we just created.
        }
    }

    private Vault resolveImportVault(User owner, String vaultName) {
        String name = (vaultName == null || vaultName.isBlank())
                ? DEFAULT_IMPORTED_VAULT
                : vaultName.trim();
        return vaultRepository.findByOwnerIdAndName(owner.getId(), name)
                .orElseGet(() -> vaultRepository.save(Vault.builder()
                        .name(name)
                        .description("Auto-created during credential import")
                        .owner(owner)
                        .build()));
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static String safe(String value, int max) {
        if (value == null) return null;
        String trimmed = value.length() > max ? value.substring(0, max) : value;
        return trimmed.replaceAll("[\\x00-\\x1F\\x7F]", "");
    }
}
