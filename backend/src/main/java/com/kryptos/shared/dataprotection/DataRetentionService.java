package com.kryptos.shared.dataprotection;

import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;

import static com.kryptos.shared.dataprotection.RetentionAction.*;

@Service
public class DataRetentionService {

    private static final Map<DataClassification, DataRetentionPolicy> RETENTION_POLICIES;

    static {
        RETENTION_POLICIES = new EnumMap<>(DataClassification.class);
        RETENTION_POLICIES.put(DataClassification.PUBLIC, new DataRetentionPolicy(null, REVIEW));
        RETENTION_POLICIES.put(DataClassification.INTERNAL, new DataRetentionPolicy(Duration.ofDays(365), REVIEW));
        RETENTION_POLICIES.put(DataClassification.CONFIDENTIAL, new DataRetentionPolicy(Duration.ofDays(90), DELETE));
        RETENTION_POLICIES.put(DataClassification.RESTRICTED, new DataRetentionPolicy(Duration.ofDays(30), DELETE));
    }

    public DataRetentionPolicy getRetentionPolicy(DataClassification classification) {
        return RETENTION_POLICIES.get(classification);
    }

    public DataRetentionPolicy getRetentionPolicy(SensitiveDataElement element) {
        return getRetentionPolicy(element.getClassification());
    }

    public boolean isExpired(DataClassification classification, Instant createdAt, Instant now) {
        DataRetentionPolicy policy = getRetentionPolicy(classification);
        if (!policy.hasExpiry()) {
            return false;
        }
        Instant expiry = createdAt.plus(policy.retentionDuration());
        return now.isAfter(expiry);
    }

    public boolean isExpired(SensitiveDataElement element, Instant createdAt, Instant now) {
        return isExpired(element.getClassification(), createdAt, now);
    }

    public Instant getExpiryDate(DataClassification classification, Instant createdAt) {
        DataRetentionPolicy policy = getRetentionPolicy(classification);
        if (!policy.hasExpiry()) {
            return null;
        }
        return createdAt.plus(policy.retentionDuration());
    }

    public Instant getExpiryDate(SensitiveDataElement element, Instant createdAt) {
        return getExpiryDate(element.getClassification(), createdAt);
    }
}
