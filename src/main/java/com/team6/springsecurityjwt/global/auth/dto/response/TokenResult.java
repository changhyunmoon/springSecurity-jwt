package com.team6.springsecurityjwt.global.auth.dto.response;

public record TokenResult(
        String accessToken,
        String refreshToken,
        String tokenType,
        Long accessTokenExpiresIn
) {
}