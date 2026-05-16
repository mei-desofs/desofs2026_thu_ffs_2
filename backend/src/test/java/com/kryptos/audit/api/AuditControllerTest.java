package com.kryptos.audit.api;

import com.kryptos.audit.domain.AuditLog;
import com.kryptos.audit.domain.AuditLogRepository;
import com.kryptos.shared.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuditController.class)
class AuditControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuditLogRepository auditLogRepository;

    @MockitoBean
    private JwtService jwtService;

    @Test
    @WithMockUser(roles = "ADMIN")
    void findAll_shouldReturn200ForAdmin() throws Exception {
        Page<AuditLog> page = new PageImpl<>(List.of(), PageRequest.of(0, 20), 0);
        when(auditLogRepository.findAll(any(PageRequest.class))).thenReturn(page);

        mockMvc.perform(get("/api/audit"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "AUDITOR")
    void findAll_shouldReturn200ForAuditor() throws Exception {
        Page<AuditLog> page = new PageImpl<>(List.of(), PageRequest.of(0, 20), 0);
        when(auditLogRepository.findAll(any(PageRequest.class))).thenReturn(page);

        mockMvc.perform(get("/api/audit"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void findByAction_shouldReturn200ForAdmin() throws Exception {
        Page<AuditLog> page = new PageImpl<>(List.of(), PageRequest.of(0, 20), 0);
        when(auditLogRepository.findAllByAction(any(), any(PageRequest.class))).thenReturn(page);

        mockMvc.perform(get("/api/audit/action/LOGIN"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(roles = "AUDITOR")
    void findByAction_shouldReturn200ForAuditor() throws Exception {
        Page<AuditLog> page = new PageImpl<>(List.of(), PageRequest.of(0, 20), 0);
        when(auditLogRepository.findAllByAction(any(), any(PageRequest.class))).thenReturn(page);

        mockMvc.perform(get("/api/audit/action/LOGIN"))
                .andExpect(status().isOk());
    }

    @Test
    void findAll_shouldReturn401WhenUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/audit"))
                .andExpect(status().isUnauthorized());
    }
}
