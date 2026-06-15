package com.kryptos.shared.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

@ExtendWith(MockitoExtension.class)
class HmacAuthenticationFilterTest {

    @Mock
    private HmacService hmacService;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private HmacAuthenticationFilter filter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    void testSwaggerUiIsIgnored() throws ServletException, IOException {
        request.setRequestURI("/swagger-ui/index.html");
        
        filter.doFilterInternal(request, response, filterChain);
        
        verify(filterChain).doFilter(request, response);
        verify(hmacService, never()).verifySignature(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    void testMissingHeadersReturnsUnauthorized() throws ServletException, IOException {
        request.setRequestURI("/api/vaults");
        
        filter.doFilterInternal(request, response, filterChain);
        
        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void testInvalidTimestampReturnsUnauthorized() throws ServletException, IOException {
        request.setRequestURI("/api/vaults");
        request.addHeader("X-Timestamp", "invalid");
        request.addHeader("X-Signature", "some-signature");
        
        when(hmacService.isValidTimestamp("invalid")).thenReturn(false);
        
        filter.doFilterInternal(request, response, filterChain);
        
        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void testValidSignatureContinuesFilterChain() throws ServletException, IOException {
        request.setRequestURI("/api/vaults");
        request.setMethod("POST");
        request.addHeader("X-Timestamp", "123456");
        request.addHeader("X-Signature", "valid-signature");
        request.setContent("test-body".getBytes());
        
        when(hmacService.isValidTimestamp("123456")).thenReturn(true);
        when(hmacService.verifySignature("valid-signature", "123456", "POST", "/api/vaults", "test-body")).thenReturn(true);
        
        filter.doFilterInternal(request, response, filterChain);
        
        verify(filterChain).doFilter(any(CachedBodyHttpServletRequest.class), any());
        assertEquals(HttpStatus.OK.value(), response.getStatus());
    }
}
