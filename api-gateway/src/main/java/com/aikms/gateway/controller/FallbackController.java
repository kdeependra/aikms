package com.aikms.gateway.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class FallbackController {

    @GetMapping("/")
    public Map<String, Object> root() {
        return Map.of(
                "service", "AI-KMS API Gateway",
                "status",  "UP",
                "routes", Map.of(
                        "auth",   "/api/v1/auth/**",
                        "keys",   "/api/v1/namespaces/**",
                        "audit",  "/api/v1/audit/**",
                        "policy", "/api/v1/policies/**"
                ),
                "health", "/actuator/health"
        );
    }

    @RequestMapping("/fallback")
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public Map<String, String> fallback() {
        return Map.of(
                "status",  "503",
                "error",   "Service Unavailable",
                "message", "The downstream service is currently unavailable. Please try again later."
        );
    }
}
