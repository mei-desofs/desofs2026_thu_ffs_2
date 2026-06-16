package com.kryptos.shared.exception;

public class ReauthenticationRequiredException extends RuntimeException {
    public ReauthenticationRequiredException(String message) {
        super(message);
    }
}
