package com.team6.springsecurityjwt.global.security.jwt;

import com.team6.springsecurityjwt.global.config.CookieProperties;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class TokenInjector {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtTokenProvider jwtTokenProvider;
    private final CookieProperties cookieProperties;

    public void injectAccessToken(String accessToken, HttpServletResponse response) {
        response.setHeader(AUTHORIZATION_HEADER, BEARER_PREFIX + accessToken);
    }

    public void injectRefreshToken(String refreshToken, HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, createRefreshTokenCookie(refreshToken).toString());
    }

    public void invalidateRefreshToken(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, deleteRefreshTokenCookie().toString());
    }

    private ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from(cookieProperties.name(), refreshToken)
                .httpOnly(true)
                .secure(cookieProperties.secure())
                .path(cookieProperties.path())
                .maxAge(Duration.ofSeconds(jwtTokenProvider.getRefreshTokenExpiresIn()))
                .sameSite(cookieProperties.sameSite())
                .build();
    }

    private ResponseCookie deleteRefreshTokenCookie() {
        return ResponseCookie.from(cookieProperties.name(), "")
                .httpOnly(true)
                .secure(cookieProperties.secure())
                .path(cookieProperties.path())
                .maxAge(0)
                .sameSite(cookieProperties.sameSite())
                .build();
    }
}
