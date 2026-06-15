package com.kryptos.shared.dataprotection;

import java.time.Duration;

public record DataRetentionPolicy(
        Duration retentionDuration,
        RetentionAction actionOnExpiry
) {
    public boolean hasExpiry() {
        return retentionDuration != null && !retentionDuration.isZero() && !retentionDuration.isNegative();
    }
}
