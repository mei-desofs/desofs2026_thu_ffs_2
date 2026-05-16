package com.kryptos.filehandling;

import com.kryptos.filehandling.application.ImportExportRateLimiter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImportExportRateLimiterTest {

    @Test
    void tryAcquireExport_allowsFivePerMinute_thenThrottles() {
        // R11 — export endpoint abuse: budget is 5/min/principal.
        ImportExportRateLimiter limiter = new ImportExportRateLimiter();
        for (int i = 0; i < 5; i++) {
            assertTrue(limiter.tryAcquireExport("alice"));
        }
        assertFalse(limiter.tryAcquireExport("alice"), "6th call must be throttled");
    }

    @Test
    void principalsAreTrackedIndependently() {
        ImportExportRateLimiter limiter = new ImportExportRateLimiter();
        for (int i = 0; i < 5; i++) {
            limiter.tryAcquireExport("alice");
        }
        assertFalse(limiter.tryAcquireExport("alice"));
        // Bob's budget must not be affected by Alice's exhaustion.
        assertTrue(limiter.tryAcquireExport("bob"));
    }
}
