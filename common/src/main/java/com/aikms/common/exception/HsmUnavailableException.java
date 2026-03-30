package com.aikms.common.exception;

import org.springframework.http.HttpStatus;

public class HsmUnavailableException extends AikmsException {
    public HsmUnavailableException(String detail) {
        super("HSM_UNAVAILABLE", "HSM is unavailable: " + detail, HttpStatus.SERVICE_UNAVAILABLE);
    }

    public HsmUnavailableException(String detail, Throwable cause) {
        super("HSM_UNAVAILABLE", "HSM is unavailable: " + detail, HttpStatus.SERVICE_UNAVAILABLE, cause);
    }
}
