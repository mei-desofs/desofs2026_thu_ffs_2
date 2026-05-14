package com.kryptos.filehandling.application;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

@Service
public class FileHandlingService {

    @Value("${kryptos.storage.temp-dir}")
    private String tempDir;

    public Path exportCredentials(List<String> encryptedData, String filename) throws IOException {
        // TODO: create temp dir, write encrypted file, return path
        return null;
    }

    public List<String> importCredentials(Path filePath) throws IOException {
        // TODO: read file, parse encrypted lines, return list
        return List.of();
    }

    public void secureDelete(Path filePath) throws IOException {
        // TODO: overwrite file content before deletion (secure wipe)
    }
}
