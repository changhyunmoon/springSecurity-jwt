package com.team6.springsecurityjwt.global.auth.controller;

import com.team6.springsecurityjwt.global.auth.dto.request.LoginRequest;
import com.team6.springsecurityjwt.global.auth.dto.response.LoginResponse;
import com.team6.springsecurityjwt.global.auth.dto.response.TokenResult;
import com.team6.springsecurityjwt.global.auth.service.AuthService;
import com.team6.springsecurityjwt.global.security.CustomUserDetails;
import com.team6.springsecurityjwt.global.security.jwt.TokenInjector;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TokenInjector tokenInjector;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse servletResponse
    ) {
        TokenResult result = authService.login(request);
        tokenInjector.injectRefreshToken(result.refreshToken(), servletResponse);

        LoginResponse response = new LoginResponse(
                result.accessToken(),
                result.tokenType(),
                result.accessTokenExpiresIn()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @AuthenticationPrincipal CustomUserDetails userDetails,
            HttpServletResponse servletResponse
    ) {
        authService.logout(userDetails);
        tokenInjector.invalidateRefreshToken(servletResponse);

        return ResponseEntity.noContent().build();
    }
}
