package com.aikms.kms.web;

import com.aikms.common.exception.AikmsException;
import com.aikms.common.exception.KeyNotFoundException;
import com.aikms.common.exception.KeyStateConflictException;
import com.aikms.common.exception.PolicyDeniedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(KeyNotFoundException.class)
    public ProblemDetail handleKeyNotFound(KeyNotFoundException ex) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        pd.setType(URI.create("https://aikms.io/errors/key-not-found"));
        pd.setProperty("errorCode", ex.getErrorCode());
        return pd;
    }

    @ExceptionHandler(KeyStateConflictException.class)
    public ProblemDetail handleStateConflict(KeyStateConflictException ex) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        pd.setType(URI.create("https://aikms.io/errors/state-conflict"));
        pd.setProperty("errorCode", ex.getErrorCode());
        return pd;
    }

    @ExceptionHandler(PolicyDeniedException.class)
    public ProblemDetail handlePolicyDenied(PolicyDeniedException ex) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, ex.getMessage());
        pd.setType(URI.create("https://aikms.io/errors/policy-denied"));
        pd.setProperty("errorCode", ex.getErrorCode());
        return pd;
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Validation failed");
        pd.setType(URI.create("https://aikms.io/errors/validation"));
        pd.setProperty("violations", ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .toList());
        return pd;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArg(IllegalArgumentException ex) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setType(URI.create("https://aikms.io/errors/bad-request"));
        return pd;
    }

    @ExceptionHandler(AikmsException.class)
    public ProblemDetail handleAikms(AikmsException ex) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(ex.getHttpStatus(), ex.getMessage());
        pd.setType(URI.create("https://aikms.io/errors/general"));
        pd.setProperty("errorCode", ex.getErrorCode());
        return pd;
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnknown(Exception ex) {
        log.error("Unhandled exception", ex);
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred");
    }
}
