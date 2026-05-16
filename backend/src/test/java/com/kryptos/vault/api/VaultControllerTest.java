package com.kryptos.vault.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptos.shared.security.JwtService;
import com.kryptos.shared.security.KryptosUserDetails;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.vault.application.VaultService;
import com.kryptos.vault.application.dto.CreateVaultRequest;
import com.kryptos.vault.application.dto.VaultResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(VaultController.class)
class VaultControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockitoBean private VaultService vaultService;
    @MockitoBean private JwtService jwtService;

    private KryptosUserDetails userPrincipal;
    private UUID ownerId;

    @BeforeEach
    void setUp() {
        ownerId = UUID.randomUUID();
        User user = User.builder().id(ownerId).username("testuser").role(Role.USER).active(true).build();
        userPrincipal = new KryptosUserDetails(user);
    }

    @Test
    void findAll_shouldReturn401_whenUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/vaults"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void findAll_shouldReturn200_whenUserAuthenticated() throws Exception {
        when(vaultService.findAllByOwner(ownerId)).thenReturn(List.of());

        mockMvc.perform(get("/api/vaults").with(user(userPrincipal)))
                .andExpect(status().isOk());
    }

    @Test
    void create_shouldReturn401_whenUnauthenticated() throws Exception {
        mockMvc.perform(post("/api/vaults")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateVaultRequest("My Vault", "desc"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void create_shouldReturn201_whenValidRequest() throws Exception {
        VaultResponse response = new VaultResponse(UUID.randomUUID(), "My Vault", "desc", ownerId);
        when(vaultService.create(any(CreateVaultRequest.class), any(UUID.class))).thenReturn(response);

        mockMvc.perform(post("/api/vaults")
                        .with(user(userPrincipal)).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateVaultRequest("My Vault", "desc"))))
                .andExpect(status().isCreated());
    }

    @Test
    void create_shouldReturn400_whenNameIsBlank() throws Exception {
        mockMvc.perform(post("/api/vaults")
                        .with(user(userPrincipal)).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new CreateVaultRequest("", "desc"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void findById_shouldReturn401_whenUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/vaults/" + UUID.randomUUID()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void findById_shouldReturn200_whenUserAuthenticated() throws Exception {
        UUID vaultId = UUID.randomUUID();
        VaultResponse response = new VaultResponse(vaultId, "My Vault", "desc", ownerId);
        when(vaultService.findById(any(UUID.class), any(UUID.class))).thenReturn(response);

        mockMvc.perform(get("/api/vaults/" + vaultId).with(user(userPrincipal)))
                .andExpect(status().isOk());
    }

    @Test
    void delete_shouldReturn401_whenUnauthenticated() throws Exception {
        mockMvc.perform(delete("/api/vaults/" + UUID.randomUUID()).with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void delete_shouldReturn204_whenUserAuthenticated() throws Exception {
        UUID vaultId = UUID.randomUUID();
        doNothing().when(vaultService).delete(any(UUID.class), any(UUID.class));

        mockMvc.perform(delete("/api/vaults/" + vaultId)
                        .with(user(userPrincipal)).with(csrf()))
                .andExpect(status().isNoContent());
    }
}
