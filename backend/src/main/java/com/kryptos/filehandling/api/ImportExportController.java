package com.kryptos.filehandling.api;

import com.kryptos.filehandling.application.FileHandlingService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/credentials")
@RequiredArgsConstructor
public class ImportExportController {

    private final FileHandlingService fileHandlingService;

    @PostMapping("/import")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Void> importCredentials(@RequestParam MultipartFile file) {
        // TODO: save temp file, import credentials, secure delete temp file
        return ResponseEntity.ok().build();
    }

    @GetMapping("/export")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<byte[]> exportCredentials() {
        // TODO: export credentials to encrypted file, return as download, secure delete after
        return ResponseEntity.ok().build();
    }
}
