package com.kryptos.shared.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import jakarta.servlet.ServletInputStream;

class CachedBodyHttpServletRequestTest {

    @Test
    void testCachedBodyCanBeReadMultipleTimes() throws IOException {
        String testBody = "{\"test\":\"value\"}";
        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setContent(testBody.getBytes(StandardCharsets.UTF_8));

        CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(mockRequest);

        // First read using getBodyAsString
        assertEquals(testBody, cachedRequest.getBodyAsString(), "Body should match the original content");

        // Second read using getInputStream
        ServletInputStream inputStream = cachedRequest.getInputStream();
        byte[] buffer = new byte[1024];
        int bytesRead = inputStream.read(buffer);
        String readFromStream = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
        assertEquals(testBody, readFromStream, "Stream should allow reading the same body again");

        // Third read using getReader
        String readFromReader = cachedRequest.getReader().readLine();
        assertEquals(testBody, readFromReader, "Reader should allow reading the same body again");
        
        // Final read from getBodyAsString again
        assertEquals(testBody, cachedRequest.getBodyAsString(), "Body as string should still be intact");
    }
}
