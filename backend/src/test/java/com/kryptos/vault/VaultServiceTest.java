package com.kryptos.vault;

import com.kryptos.vault.application.VaultService;
import com.kryptos.vault.domain.VaultRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class VaultServiceTest {

    @Mock
    private VaultRepository vaultRepository;

    @InjectMocks
    private VaultService vaultService;

    @Test
    void create_shouldReturnVault_whenValidRequest() {
        // TODO
    }

    @Test
    void findById_shouldThrow_whenUserDoesNotOwnVault() {
        // TODO
    }

    @Test
    void delete_shouldThrow_whenUserDoesNotOwnVault() {
        // TODO
    }
}
