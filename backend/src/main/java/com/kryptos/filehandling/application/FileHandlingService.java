package com.kryptos.filehandling.application;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class FileHandlingService {

  /** Maximum size of an import file we are willing to read (5 MiB). */
  private static final long MAX_IMPORT_BYTES = 5L * 1024 * 1024;
  /** Maximum number of lines (records) we are willing to import. */
  private static final int MAX_IMPORT_LINES = 50_000;
  /** Number of random+zero passes when securely wiping a file. */
  private static final int SECURE_WIPE_PASSES = 3;

  @Value("${kryptos.storage.temp-dir}")
  private String tempDir;

  private final AuditService auditService;

  private Path tempDirPath;

  @PostConstruct
  void initTempDir() throws IOException {
    this.tempDirPath = Paths.get(tempDir).toAbsolutePath().normalize();
    if (!Files.exists(tempDirPath)) {
      Files.createDirectories(tempDirPath);
    }
    // Best-effort harden permissions on POSIX systems.
    try {
      Set<PosixFilePermission> perms = EnumSet.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE);
      Files.setPosixFilePermissions(tempDirPath, perms);
    } catch (UnsupportedOperationException ignored) {
      // Non-POSIX FS (e.g. Windows in tests): rely on default ACLs.
    }
  }

  public Path exportCredentials(List<String> encryptedData, String filename) throws IOException {
    if (encryptedData == null) {
      throw new IllegalArgumentException("encryptedData must not be null");
    }
    String username = currentUsername();

    Path target = tempDirPath.resolve("export-" + UUID.randomUUID() + ".kvault");
    verifyWithinTempDir(target);

    try {
      // CREATE_NEW guarantees we never overwrite an existing file.
      try (var writer = Files.newBufferedWriter(target, StandardCharsets.UTF_8,
          StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
        for (String entry : encryptedData) {
          if (entry == null)
            continue;
          // Each record is on its own line. Reject embedded newlines
          // to keep the format unambiguous.
          if (entry.indexOf('\n') >= 0 || entry.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("Encrypted record contains illegal newline character");
          }
          writer.write(entry);
          writer.newLine();
        }
      }
      try {
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
      } catch (UnsupportedOperationException ignored) {
        // non-POSIX
      }
      auditService.log(AuditAction.EXPORT, username, "filehandling",
          "Exported " + encryptedData.size() + " record(s) to: " + filename);
      return target;
    } catch (IOException | RuntimeException e) {
      // Best-effort: do not leave a half-written file around, no matter
      // whether the failure was an I/O error or an input validation
      // error such as an embedded newline.
      try {
        Files.deleteIfExists(target);
      } catch (IOException ignored) {
        /* nothing else to do */ }
      auditService.log(AuditAction.EXPORT, username, "filehandling",
          "Export failed for " + filename + ": " + e.getClass().getSimpleName());
      throw e;
    }
  }

  /**
   * Read a previously written import file and return the encrypted lines.
   */
  public List<String> importCredentials(Path filePath) throws IOException {
    if (filePath == null) {
      throw new IllegalArgumentException("filePath must not be null");
    }
    String username = currentUsername();

    Path normalised = filePath.toAbsolutePath().normalize();
    verifyWithinTempDir(normalised);

    if (!Files.exists(normalised) || !Files.isRegularFile(normalised)) {
      throw new IOException("Import file not found");
    }
    long size = Files.size(normalised);
    if (size > MAX_IMPORT_BYTES) {
      auditService.log(AuditAction.IMPORT, username, "filehandling",
          "Rejected oversize import file: " + size + " bytes");
      throw new IOException("Import file is too large");
    }

    List<String> records = new ArrayList<>();
    try (var reader = Files.newBufferedReader(normalised, StandardCharsets.UTF_8)) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.isBlank())
          continue;
        records.add(line);
        if (records.size() > MAX_IMPORT_LINES) {
          auditService.log(AuditAction.IMPORT, username, "filehandling",
              "Rejected import: line count exceeds limit");
          throw new IOException("Import file has too many records");
        }
      }
    }
    auditService.log(AuditAction.IMPORT, username, "filehandling",
        "Imported " + records.size() + " record(s) from file: " + normalised.getFileName());
    return records;
  }

  public void secureDelete(Path filePath) throws IOException {
    if (filePath == null) {
      return;
    }
    String username = currentUsername();
    Path normalised = filePath.toAbsolutePath().normalize();

    // Refuse to wipe anything outside our managed temp directory.
    // R13 says this must surface as an IllegalArgumentException so callers
    // (and tests) can distinguish a misuse-by-developer from an I/O fault.
    if (!normalised.startsWith(tempDirPath)) {
      auditService.log(AuditAction.SECURE_WIPE_FAILED, username, "filehandling",
          "Rejected wipe outside temp dir: " + normalised);
      throw new IllegalArgumentException(
          "Refusing to wipe path outside temp directory");
    }

    try {
      if (Files.exists(normalised) && Files.isRegularFile(normalised)) {
        long size = Files.size(normalised);
        if (size > 0) {
          SecureRandom rng = new SecureRandom();
          byte[] buffer = new byte[(int) Math.min(size, 8192)];
          for (int pass = 0; pass < SECURE_WIPE_PASSES; pass++) {
            try (var ch = Files.newByteChannel(normalised, StandardOpenOption.WRITE)) {
              long written = 0;
              while (written < size) {
                if (pass < SECURE_WIPE_PASSES - 1) {
                  rng.nextBytes(buffer);
                } else {
                  java.util.Arrays.fill(buffer, (byte) 0);
                }
                int toWrite = (int) Math.min(buffer.length, size - written);
                ch.write(java.nio.ByteBuffer.wrap(buffer, 0, toWrite));
                written += toWrite;
              }
              ch.position(0);
            }
          }
        }
      }
      Files.deleteIfExists(normalised);
      auditService.log(AuditAction.SECURE_WIPE, username, "filehandling",
          "Secure wipe completed: " + normalised.getFileName());
    } catch (IOException | RuntimeException e) {
      // Even if overwrite failed, still make sure the file is gone.
      try {
        Files.deleteIfExists(normalised);
      } catch (IOException ignored) {
        /* keep going */ }
      auditService.log(AuditAction.SECURE_WIPE_FAILED, username, "filehandling",
          "Secure wipe failed for " + normalised.getFileName() + " - " + e.getClass().getSimpleName());
      if (e instanceof IOException ioe)
        throw ioe;
      throw new IOException("Secure wipe failed", e);
    }
  }

  public Path storeUpload(byte[] content, String originalName) throws IOException {
    if (content == null) {
      throw new IllegalArgumentException("content must not be null");
    }
    if (content.length > MAX_IMPORT_BYTES) {
      throw new IOException("Uploaded file is too large");
    }
    String extension = "";
    if (originalName != null) {
      int dot = originalName.lastIndexOf('.');
      if (dot >= 0 && dot < originalName.length() - 1) {
        String raw = originalName.substring(dot + 1);
        // Allow only conservative ASCII extension characters.
        if (raw.matches("[A-Za-z0-9]{1,8}")) {
          extension = "." + raw.toLowerCase();
        }
      }
    }
    Path target = tempDirPath.resolve("import-" + UUID.randomUUID() + extension);
    verifyWithinTempDir(target);
    Files.write(target, content,
        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    try {
      Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
    } catch (UnsupportedOperationException ignored) {
      // non-POSIX
    }
    return target;
  }

  private void verifyWithinTempDir(Path candidate) throws IOException {
    Path normalised = candidate.toAbsolutePath().normalize();
    if (!normalised.startsWith(tempDirPath)) {
      throw new IOException("Refusing to access path outside temp directory: " + normalised);
    }
  }

  private static String currentUsername() {
    var auth = SecurityContextHolder.getContext().getAuthentication();
    return auth != null ? auth.getName() : "anonymous";
  }
}
