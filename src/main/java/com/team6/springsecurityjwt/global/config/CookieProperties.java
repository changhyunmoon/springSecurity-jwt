package com.team6.springsecurityjwt.global.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "cookie.refresh-token")
public record CookieProperties(
        String name,
        String path,
        boolean secure,
        String sameSite
) {
}