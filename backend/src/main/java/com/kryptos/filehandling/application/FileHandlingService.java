package com.kryptos.filehandling.application;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

@Service
@RequiredArgsConstructor
public class FileHandlingService {

    @Value("${kryptos.storage.temp-dir}")
    private String tempDir;

    private final AuditService auditService;

    public Path exportCredentials(List<String> encryptedData, String filename) throws IOException {
        // TODO: create temp dir, write encrypted file, return path
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.EXPORT, username, "filehandling",
                "Exporting credentials to file: " + filename);
        return null;
    }

    public List<String> importCredentials(Path filePath) throws IOException {
        // TODO: read file, parse encrypted lines, return list
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        auditService.log(AuditAction.IMPORT, username, "filehandling",
                "Importing credentials from file: " + filePath.getFileName());
        return List.of();
    }

    public void secureDelete(Path filePath) throws IOException {
        // TODO: overwrite file content before deletion (secure wipe)
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        try {
            auditService.log(AuditAction.SECURE_WIPE, username, "filehandling",
                    "Secure wipe of file: " + filePath.getFileName());
        } catch (Exception e) {
            auditService.log(AuditAction.SECURE_WIPE_FAILED, username, "filehandling",
                    "Secure wipe failed for file: " + filePath.getFileName() + " - " + e.getMessage());
            throw e;
        }
    }
}
