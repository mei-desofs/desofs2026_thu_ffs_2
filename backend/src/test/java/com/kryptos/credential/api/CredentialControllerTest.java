package com.kryptos.credential.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptos.credential.application.CredentialService;
import com.kryptos.credential.application.dto.CreateCredentialRequest;
import com.kryptos.credential.application.dto.CredentialResponse;
import com.kryptos.shared.security.JwtService;
import com.kryptos.shared.security.KryptosUserDetails;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
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

@WebMvcTest(CredentialController.class)
class CredentialControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    @MockitoBean private CredentialService credentialService;
    @MockitoBean private JwtService jwtService;

    private KryptosUserDetails userPrincipal;
    private UUID ownerId;
    private UUID vaultId;

    @BeforeEach
    void setUp() {
        ownerId = UUID.randomUUID();
        vaultId = UUID.randomUUID();
        User user = User.builder().id(ownerId).username("testuser").role(Role.USER).active(true).build();
        userPrincipal = new KryptosUserDetails(user);
    }

    @Test
    void findAllByVault_shouldReturn200_whenUserAuthenticated() throws Exception {
        when(credentialService.findAllByVault(any(UUID.class), any(UUID.class))).thenReturn(List.of());

        mockMvc.perform(get("/api/credentials/vault/" + vaultId).with(user(userPrincipal)))
                .andExpect(status().isOk());
    }

    @Test
    void create_shouldReturn401_whenUnauthenticated() throws Exception {
        CreateCredentialRequest request = new CreateCredentialRequest(
                vaultId, "GitHub", "user@email.com", "secret123", null, null);

        mockMvc.perform(post("/api/credentials")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void create_shouldReturn201_whenValidRequest() throws Exception {
        CreateCredentialRequest request = new CreateCredentialRequest(
                vaultId, "GitHub", "user@email.com", "secret123", "https://github.com", null);
        CredentialResponse response = new CredentialResponse(
                UUID.randomUUID(), "GitHub", "user@email.com", "https://github.com", null, vaultId);

        when(credentialService.create(any(CreateCredentialRequest.class), any(UUID.class))).thenReturn(response);

        mockMvc.perform(post("/api/credentials")
                        .with(user(userPrincipal)).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }

    @Test
    void create_shouldReturn400_whenServiceNameIsBlank() throws Exception {
        CreateCredentialRequest request = new CreateCredentialRequest(
                vaultId, "", "user@email.com", "secret123", null, null);

        mockMvc.perform(post("/api/credentials")
                        .with(user(userPrincipal)).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void create_shouldReturn400_whenVaultIdIsNull() throws Exception {
        CreateCredentialRequest request = new CreateCredentialRequest(
                null, "GitHub", "user@email.com", "secret123", null, null);

        mockMvc.perform(post("/api/credentials")
                        .with(user(userPrincipal)).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void findById_shouldReturn401_whenUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/credentials/" + UUID.randomUUID()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void findById_shouldReturn200_whenUserAuthenticated() throws Exception {
        UUID credId = UUID.randomUUID();
        CredentialResponse response = new CredentialResponse(
                credId, "GitHub", "user@email.com", "https://github.com", null, vaultId);
        when(credentialService.findById(any(UUID.class), any(UUID.class))).thenReturn(response);

        mockMvc.perform(get("/api/credentials/" + credId).with(user(userPrincipal)))
                .andExpect(status().isOk());
    }

    @Test
    void delete_shouldReturn401_whenUnauthenticated() throws Exception {
        mockMvc.perform(delete("/api/credentials/" + UUID.randomUUID()).with(csrf()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void delete_shouldReturn204_whenUserAuthenticated() throws Exception {
        UUID credId = UUID.randomUUID();
        doNothing().when(credentialService).delete(any(UUID.class), any(UUID.class));

        mockMvc.perform(delete("/api/credentials/" + credId)
                        .with(user(userPrincipal)).with(csrf()))
                .andExpect(status().isNoContent());
    }
}
