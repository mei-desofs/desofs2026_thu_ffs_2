package com.kryptos.credential;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptos.credential.application.dto.UpdateCredentialRequest;
import com.kryptos.credential.domain.Credential;
import com.kryptos.credential.domain.CredentialRepository;
import com.kryptos.shared.security.JwtService;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;
import com.kryptos.vault.domain.Vault;
import com.kryptos.vault.domain.VaultRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class CredentialIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private VaultRepository vaultRepository;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private JwtService jwtService;

    private User user1;
    private User user2;
    private String user1Token;
    private String user2Token;
    private Credential user1Credential;
    private Credential user2Credential;

    @BeforeEach
    void setUp() {
        credentialRepository.deleteAll();
        vaultRepository.deleteAll();
        userRepository.deleteAll();

        // Setup User 1
        user1 = User.builder().username("user1").email("user1@test.com").password("pass1").role(Role.USER).build();
        userRepository.save(user1);
        user1Token = jwtService.generateToken(user1.getUsername(), user1.getRole().name());

        Vault vault1 = Vault.builder().name("Vault 1").owner(user1).build();
        vaultRepository.save(vault1);

        user1Credential = Credential.builder().serviceName("Service 1").username("user").encryptedPassword("enc").vault(vault1).build();
        credentialRepository.save(user1Credential);

        // Setup User 2
        user2 = User.builder().username("user2").email("user2@test.com").password("pass2").role(Role.USER).build();
        userRepository.save(user2);
        user2Token = jwtService.generateToken(user2.getUsername(), user2.getRole().name());

        Vault vault2 = Vault.builder().name("Vault 2").owner(user2).build();
        vaultRepository.save(vault2);

        user2Credential = Credential.builder().serviceName("Service 2").username("user").encryptedPassword("enc").vault(vault2).build();
        credentialRepository.save(user2Credential);
    }

    @Test
    void user1_cannotUpdateCredential_ofUser2() throws Exception {
        UpdateCredentialRequest request = new UpdateCredentialRequest("Hacked Service", "hackedUser", "newPass", null, null);

        mockMvc.perform(put("/api/credentials/" + user2Credential.getId())
                .header("Authorization", "Bearer " + user1Token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isForbidden());
    }

    @Test
    void updateCredential_shouldRejectInvalidInput() throws Exception {
        UpdateCredentialRequest request = new UpdateCredentialRequest("", "", "", null, null);

        mockMvc.perform(put("/api/credentials/" + user1Credential.getId())
                .header("Authorization", "Bearer " + user1Token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest());
    }

    @Test
    void updateCredential_shouldEncryptPasswordAndReturnUpdatedCredential() throws Exception {
        UpdateCredentialRequest request = new UpdateCredentialRequest("New Service", "newUser", "plainPassword123", "http://new.url", "notes");

        mockMvc.perform(put("/api/credentials/" + user1Credential.getId())
                .header("Authorization", "Bearer " + user1Token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.serviceName").value("New Service"))
            .andExpect(jsonPath("$.username").value("newUser"));

        Credential updated = credentialRepository.findById(user1Credential.getId()).orElseThrow();
        assertNotEquals("plainPassword123", updated.getEncryptedPassword());
    }

    @Test
    void updateCredential_shouldFail_whenCredentialDoesNotExist() throws Exception {
        UpdateCredentialRequest request = new UpdateCredentialRequest("Service", "user", "pass", null, null);
        UUID fakeId = UUID.randomUUID();

        mockMvc.perform(put("/api/credentials/" + fakeId)
                .header("Authorization", "Bearer " + user1Token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isForbidden()); // "Credential not found or access denied" results in ForbiddenException
    }

    @Test
    void updateCredential_shouldReject_whenServiceNameIsTooLong() throws Exception {
        String longServiceName = "a".repeat(101); // Max size is 100
        UpdateCredentialRequest request = new UpdateCredentialRequest(longServiceName, "user", "pass", null, null);

        mockMvc.perform(put("/api/credentials/" + user1Credential.getId())
                .header("Authorization", "Bearer " + user1Token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isBadRequest());
    }

    @Test
    void updateCredential_shouldAllow_whenOptionalFieldsAreNull() throws Exception {
        UpdateCredentialRequest request = new UpdateCredentialRequest("Service", "user", "pass", null, null);

        mockMvc.perform(put("/api/credentials/" + user1Credential.getId())
                .header("Authorization", "Bearer " + user1Token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.serviceName").value("Service"));
    }
}
