package com.aikms.common.exception;

import org.springframework.http.HttpStatus;

public class PolicyDeniedException extends AikmsException {
    public PolicyDeniedException(String identity, String operation, String resource) {
        super("POLICY_DENIED",
              "Identity '%s' is not permitted to perform '%s' on '%s'".formatted(identity, operation, resource),
              HttpStatus.FORBIDDEN);
    }

    public PolicyDeniedException(String message) {
        super("POLICY_DENIED", message, HttpStatus.FORBIDDEN);
    }
}
