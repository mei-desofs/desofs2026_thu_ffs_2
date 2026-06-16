package com.kryptos.shared.validation;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PasswordValidator {

    private static final Set<String> FORBIDDEN_WORDS = new HashSet<>(Arrays.asList(
            "password", "kryptos", "user", "admin", "root", "test",
            "123456", "12345678", "qwerty", "abc123", "password123",
            "admin123", "root123", "kryptos123", "kryptos@", "kryptos#",
            "kryptos!", "username", "email", "secret", "login"
    ));

    public static boolean containsForbiddenWord(String password) {
        if (password == null || password.isEmpty()) {
            return false;
        }

        String lowerPassword = password.toLowerCase();
        return FORBIDDEN_WORDS.stream()
                .anyMatch(lowerPassword::contains);
    }

    public static void validatePassword(String password) throws IllegalArgumentException {
        if (containsForbiddenWord(password)) {
            throw new IllegalArgumentException(
                    "Password contains forbidden word. Choose a more unique password.");
        }
    }
}
