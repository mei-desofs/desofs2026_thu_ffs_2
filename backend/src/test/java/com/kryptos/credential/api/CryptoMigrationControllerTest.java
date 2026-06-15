package com.kryptos.credential.api;

import com.kryptos.credential.application.CryptoMigrationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class CryptoMigrationControllerTest {

    private MockMvc mockMvc;

    @Mock
    private CryptoMigrationService cryptoMigrationService;

    @InjectMocks
    private CryptoMigrationController cryptoMigrationController;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(cryptoMigrationController).build();
    }

    @Test
    void migrateCrypto_shouldReturnSuccessResponse() throws Exception {
        when(cryptoMigrationService.migrateAllCredentials()).thenReturn(5);

        mockMvc.perform(post("/api/admin/crypto/migrate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Crypto migration completed successfully."))
                .andExpect(jsonPath("$.migratedRecords").value(5));
    }
}
