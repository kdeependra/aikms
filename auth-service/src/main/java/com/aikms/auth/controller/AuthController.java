package com.aikms.auth.controller;

import com.aikms.auth.dto.*;
import com.aikms.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public TokenResponse login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest http) throws Exception {
        return authService.login(request,
                http.getRemoteAddr(),
                http.getHeader("User-Agent"));
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request, HttpServletRequest http) throws Exception {
        return authService.refresh(request, http.getRemoteAddr(), http.getHeader("User-Agent"));
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody RefreshRequest request) throws Exception {
        authService.logout(request.refreshToken());
    }
}
