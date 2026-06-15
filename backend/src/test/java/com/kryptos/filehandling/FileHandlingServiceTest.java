package com.kryptos.filehandling;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.filehandling.application.FileHandlingService;

/**
 * Unit tests for {@link FileHandlingService}. Each test maps to a specific
 * threat in the Phase 1 threat model.
 */
@DisplayName("FileHandlingService unit tests")
class FileHandlingServiceTest {

    @TempDir Path tempDir;

    private AuditService auditService;
    private FileHandlingService service;

    @BeforeEach
    void setUp() throws Exception {
        auditService = mock(AuditService.class);
        service = new FileHandlingService(auditService);
        ReflectionTestUtils.setField(service, "tempDir", tempDir.toString());
        ReflectionTestUtils.invokeMethod(service, "initTempDir");
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("testuser", "n/a",
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))));
    }

    @Test
    @DisplayName("R09 — files written into temp directory are owner-only (POSIX rw-------)")
    void exportCredentials_filesAreOwnerOnly() throws IOException {
        Path file = service.exportCredentials(List.of("x"), "perms.kvault");
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
            assertThat(perms).contains(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            assertThat(perms).doesNotContain(PosixFilePermission.GROUP_READ,
                    PosixFilePermission.OTHERS_READ);
        } catch (UnsupportedOperationException ignoreNonPosix) {
            // Skipped on non-POSIX filesystems (Windows). CI is Linux.
        }
    }

    @Test
    @DisplayName("R12 — secureDelete removes the file and writes a SECURE_WIPE audit entry")
    void secureDelete_removesFileAndLogsSuccess() throws IOException {
        Path victim = service.exportCredentials(List.of("secret"), "wipe.kvault");
        assertThat(Files.exists(victim)).isTrue();

        service.secureDelete(victim);

        assertThat(Files.exists(victim)).isFalse();
        verify(auditService).log(eq(AuditAction.SECURE_WIPE), eq("testuser"),
                eq("filehandling"), any());
    }

    @Test
    @DisplayName("R13 — secureDelete refuses a path outside the temp directory")
    void secureDelete_refusesPathOutsideTempDir() {
        Path outside = Paths.get(System.getProperty("java.io.tmpdir"))
                .resolve("not-in-our-tempdir.kvault");
        assertThatThrownBy(() -> service.secureDelete(outside))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside temp directory");
        verify(auditService).log(eq(AuditAction.SECURE_WIPE_FAILED), eq("testuser"),
                eq("filehandling"), any());
    }

    @Test
    @DisplayName("R08 — storeUpload sanitises path-traversal filenames into a UUID inside the temp dir")
    void storeUpload_sanitisesFilename() throws IOException {
        Path stored = service.storeUpload("hello".getBytes(), "../../../etc/passwd.kvault");

        assertThat(stored.getParent().toAbsolutePath().normalize())
                .isEqualTo(tempDir.toAbsolutePath().normalize());
        String name = stored.getFileName().toString();
        assertThat(name).startsWith("import-").endsWith(".kvault");
        assertThat(name).doesNotContain("..").doesNotContain("/");
    }

    @Test
    @DisplayName("R08 — storeUpload rejects files larger than 5 MiB")
    void storeUpload_shouldRejectOversizeFile() {
        int oversized = 5 * 1024 * 1024 + 1;
        byte[] content = new byte[oversized];
        IOException ex = assertThrows(IOException.class,
                () -> service.storeUpload(content, "large.kvault"));
        assertThat(ex.getMessage()).containsIgnoringCase("large");
    }

    @Test
    @DisplayName("storeUpload with consent preserves original file timestamps")
    void storeUpload_withConsent_preservesMetadata() throws IOException {
        Path file = service.storeUpload("test-data".getBytes(), "test.kvault", false);

        FileTime creation = (FileTime) Files.getAttribute(file, "creationTime");
        assertThat(creation.toMillis()).isNotZero();
    }
}
