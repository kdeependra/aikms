package com.aikms.common.exception;

import org.springframework.http.HttpStatus;

public class KeyNotFoundException extends AikmsException {
    public KeyNotFoundException(String keyId) {
        super("KEY_NOT_FOUND", "Key not found: " + keyId, HttpStatus.NOT_FOUND);
    }
}
