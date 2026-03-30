package com.aikms.common.exception;

import org.springframework.http.HttpStatus;

public class AikmsException extends RuntimeException {

    private final String errorCode;
    private final HttpStatus httpStatus;

    public AikmsException(String errorCode, String message, HttpStatus httpStatus) {
        super(message);
        this.errorCode = errorCode;
        this.httpStatus = httpStatus;
    }

    public AikmsException(String errorCode, String message, HttpStatus httpStatus, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.httpStatus = httpStatus;
    }

    public String getErrorCode() { return errorCode; }
    public HttpStatus getHttpStatus() { return httpStatus; }
}
