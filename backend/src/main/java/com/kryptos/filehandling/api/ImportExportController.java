package com.kryptos.filehandling.api;

import com.kryptos.filehandling.application.CredentialImportExportService;
import com.kryptos.filehandling.application.ImportExportRateLimiter;
import com.kryptos.shared.exception.RateLimitExceededException;
import com.kryptos.shared.security.KryptosUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/credentials")
@RequiredArgsConstructor
public class ImportExportController {

  /** Hard cap on the size of an uploaded import file (5 MiB). */
  private static final long MAX_UPLOAD_BYTES = 5L * 1024 * 1024;

  private final CredentialImportExportService importExportService;
  private final ImportExportRateLimiter rateLimiter;

  @PostMapping(value = "/import", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @PreAuthorize("hasRole('USER')")
  public ResponseEntity<Map<String, Object>> importCredentials(
      @RequestParam("file") MultipartFile file,
      @RequestParam(name = "consentToStorage", defaultValue = "false") boolean consentToStorage,
      @AuthenticationPrincipal KryptosUserDetails principal) throws IOException {
    if (file == null || file.isEmpty()) {
      return ResponseEntity.badRequest().body(Map.of("error", "File is required"));
    }
    if (file.getSize() > MAX_UPLOAD_BYTES) {
      // R08 — oversize upload → 413 per Security Test Plan V2.
      return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
          .body(Map.of("error", "File too large"));
    }
    if (!rateLimiter.tryAcquireImport(principal.getUsername())) {
      throw new RateLimitExceededException("Too many import attempts. Try again later.");
    }
    int imported = importExportService.importForOwner(
        file.getBytes(), file.getOriginalFilename(), principal.getId(), consentToStorage);
    return ResponseEntity.ok(Map.of("imported", imported));
  }

  @GetMapping("/export")
  @PreAuthorize("hasRole('USER')")
  public ResponseEntity<byte[]> exportCredentials(
      @AuthenticationPrincipal KryptosUserDetails principal) throws IOException {
    if (!rateLimiter.tryAcquireExport(principal.getUsername())) {
      // R11 — export endpoint abuse → 429.
      throw new RateLimitExceededException("Too many export attempts. Try again later.");
    }
    byte[] bytes = importExportService.exportForOwner(principal.getId());
    return ResponseEntity.ok()
        .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE)
        .header(HttpHeaders.CONTENT_DISPOSITION,
            "attachment; filename=\"kryptos-export.kvault\"")
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .body(bytes);
  }
}
