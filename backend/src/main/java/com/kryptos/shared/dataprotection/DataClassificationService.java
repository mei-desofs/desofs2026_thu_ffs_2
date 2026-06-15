package com.kryptos.shared.dataprotection;

import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class DataClassificationService {

    private static final Map<DataClassification, List<ProtectionRequirement>> PROTECTION_REQUIREMENTS;
    private static final Map<DataClassification, List<String>> COMPLIANCE_MAPPINGS;

    static {
        PROTECTION_REQUIREMENTS = new EnumMap<>(DataClassification.class);
        PROTECTION_REQUIREMENTS.put(DataClassification.PUBLIC, List.of(
                new ProtectionRequirement("Integrity", "Ensure data integrity via standard mechanisms (e.g., checksums where appropriate)."),
                new ProtectionRequirement("Availability", "Standard availability requirements apply."),
                new ProtectionRequirement("Logging", "No restrictions; data can be logged freely.")
        ));
        PROTECTION_REQUIREMENTS.put(DataClassification.INTERNAL, List.of(
                new ProtectionRequirement("Access Control", "Restrict access to authenticated users with a legitimate need."),
                new ProtectionRequirement("Transit", "Transmit over TLS in production environments."),
                new ProtectionRequirement("Integrity", "Protect against unauthorized modification via access controls."),
                new ProtectionRequirement("Logging", "Data may appear in logs but restrict log access to authorized personnel. Minimize unnecessary logging."),
                new ProtectionRequirement("Privacy", "Apply data minimization principle \u2014 only collect and retain what is necessary for the intended purpose.")
        ));
        PROTECTION_REQUIREMENTS.put(DataClassification.CONFIDENTIAL, List.of(
                new ProtectionRequirement("Encryption at Rest", "Encrypt with AES-256-GCM or equivalent; keys managed separately."),
                new ProtectionRequirement("Encryption in Transit", "Always transmit over TLS; enforce HSTS."),
                new ProtectionRequirement("Access Control", "Strict need-to-know access; audit all access events, including log access."),
                new ProtectionRequirement("Encoding Awareness", "Recognize that Base64, JWT payloads, and similar encodings are NOT encryption. Treat encoded data as plaintext for classification purposes."),
                new ProtectionRequirement("Key Rotation", "Support cryptographic key rotation (e.g., EncryptionService V1/V2 key versions)."),
                new ProtectionRequirement("Integrity", "Use authenticated encryption (AES-GCM) to provide integrity and confidentiality."),
                new ProtectionRequirement("Retention", DataClassification.CONFIDENTIAL.getRetentionGuidance()),
                new ProtectionRequirement("Logging", "Must be masked or redacted in all log outputs. Never log plaintext values (passwords, tokens, 2FA codes). Audit all log access events involving this data."),
                new ProtectionRequirement("Database Encryption", "Use database-level encryption (TDE or encrypted columns) as a defense-in-depth measure alongside application-layer encryption."),
                new ProtectionRequirement("Privacy", "Apply pseudonymization where feasible. Enforce data minimization and purpose limitation principles.")
        ));
        PROTECTION_REQUIREMENTS.put(DataClassification.RESTRICTED, List.of(
                new ProtectionRequirement("Encryption at Rest", "Encrypt with strong algorithm (AES-256-GCM); keys stored in a secure vault or environment variable."),
                new ProtectionRequirement("Encryption in Transit", "Always transmit over TLS with strong ciphers; never transmit in plaintext."),
                new ProtectionRequirement("Access Control", "Strictly limited to administrators and the specific service component; all access must be audited, including any log access."),
                new ProtectionRequirement("Key Rotation", "Mandatory regular rotation. The EncryptionService already supports key rotation via previous-secret fallback."),
                new ProtectionRequirement("Storage", "Never store in logs, error messages, or source code (use environment variables)."),
                new ProtectionRequirement("Retention", DataClassification.RESTRICTED.getRetentionGuidance()),
                new ProtectionRequirement("Regulatory Compliance", "Subject to GDPR, data protection regulations, and contractual obligations. Personal data (Art. 4 GDPR) must be identified and handled accordingly."),
                new ProtectionRequirement("Logging", "Must never appear in logs, error messages, exceptions, or stack traces. If forensic reference is absolutely necessary, use a SHA-256 hash of the value only."),
                new ProtectionRequirement("Database Encryption", "Database-level encryption (TDE) is mandatory. Use column-level encryption for sensitive fields in addition to application-layer AES-256-GCM."),
                new ProtectionRequirement("Privacy", "Apply pseudonymization or anonymization where feasible. Conduct a Data Protection Impact Assessment (DPIA) for any processing involving this data. Strict purpose limitation applies.")
        ));

        COMPLIANCE_MAPPINGS = new EnumMap<>(DataClassification.class);
        COMPLIANCE_MAPPINGS.put(DataClassification.RESTRICTED, List.of("GDPR Art. 32 (Security of Processing)", "GDPR Art. 5(1)(f) (Integrity & Confidentiality)"));
        COMPLIANCE_MAPPINGS.put(DataClassification.CONFIDENTIAL, List.of("GDPR Art. 32 (Security of Processing)"));
        COMPLIANCE_MAPPINGS.put(DataClassification.INTERNAL, List.of("GDPR Art. 5(1)(c) (Data Minimisation)"));
        COMPLIANCE_MAPPINGS.put(DataClassification.PUBLIC, List.of());
    }

    public DataClassification classify(String fieldPath) {
        return Arrays.stream(SensitiveDataElement.values())
                .filter(e -> e.getFieldPath().equals(fieldPath))
                .findFirst()
                .map(SensitiveDataElement::getClassification)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unknown data element: " + fieldPath + ". All data elements must be registered in SensitiveDataElement."));
    }

    public SensitiveDataElement getElement(String fieldPath) {
        return Arrays.stream(SensitiveDataElement.values())
                .filter(e -> e.getFieldPath().equals(fieldPath))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unknown data element: " + fieldPath));
    }

    public List<ProtectionRequirement> getProtectionRequirements(DataClassification classification) {
        return PROTECTION_REQUIREMENTS.getOrDefault(classification, List.of());
    }

    public List<String> getApplicableRegulations(DataClassification classification) {
        return COMPLIANCE_MAPPINGS.getOrDefault(classification, List.of());
    }

    public List<SensitiveDataElement> getElementsByClassification(DataClassification classification) {
        return Arrays.stream(SensitiveDataElement.values())
                .filter(e -> e.getClassification() == classification)
                .collect(Collectors.toList());
    }

    public boolean isProperlyProtected(SensitiveDataElement element, boolean isEncryptedAtRest,
                                        boolean isEncryptedInTransit, boolean hasAccessControl,
                                        boolean hasLoggingProtection, boolean hasDatabaseEncryption,
                                        boolean hasPrivacyEnhancement) {
        DataClassification cls = element.getClassification();
        if (cls.isRequiresEncryptionAtRest() && !isEncryptedAtRest) return false;
        if (cls.isRequiresEncryptionInTransit() && !isEncryptedInTransit) return false;
        if (cls.isRequiresStrictAccessControl() && !hasAccessControl) return false;
        if (cls.isRequiresLoggingProtection() && !hasLoggingProtection) return false;
        if (cls.isRequiresDatabaseEncryption() && !hasDatabaseEncryption) return false;
        return !cls.isRequiresPrivacyEnhancement() || hasPrivacyEnhancement;
    }

    public boolean isEncodedOnly(DataClassification classification) {
        return classification == DataClassification.CONFIDENTIAL;
    }

    public Optional<DataClassification> getClassificationForElement(String fieldPath) {
        return Arrays.stream(SensitiveDataElement.values())
                .filter(e -> e.getFieldPath().equals(fieldPath))
                .findFirst()
                .map(SensitiveDataElement::getClassification);
    }

    public Set<String> getAllFieldPaths() {
        return Arrays.stream(SensitiveDataElement.values())
                .map(SensitiveDataElement::getFieldPath)
                .collect(Collectors.toSet());
    }

    public long countElementsAtLevel(DataClassification classification) {
        return Arrays.stream(SensitiveDataElement.values())
                .filter(e -> e.getClassification() == classification)
                .count();
    }

    public record ProtectionRequirement(String category, String requirement) {
    }
}
