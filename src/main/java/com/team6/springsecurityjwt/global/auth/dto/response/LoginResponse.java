package com.team6.springsecurityjwt.global.auth.dto.response;

public record LoginResponse(
        String accessToken,
        String tokenType,
        Long accessTokenExpiresIn
) {
}