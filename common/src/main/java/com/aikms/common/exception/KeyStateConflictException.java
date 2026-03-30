package com.aikms.common.exception;

import org.springframework.http.HttpStatus;

public class KeyStateConflictException extends AikmsException {
    public KeyStateConflictException(String keyId, String currentState, String requestedOperation) {
        super("KEY_STATE_CONFLICT",
              "Key '%s' in state '%s' cannot perform operation: %s".formatted(keyId, currentState, requestedOperation),
              HttpStatus.CONFLICT);
    }
}
