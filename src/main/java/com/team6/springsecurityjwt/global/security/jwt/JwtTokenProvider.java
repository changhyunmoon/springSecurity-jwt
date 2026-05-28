package com.team6.springsecurityjwt.global.security.jwt;

import com.team6.springsecurityjwt.member.entity.Member;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

/*
Access Token
- subject: member.uuid
- claims: type=access

Refresh Token
- subject: member.uuid
- claims: type=refresh
- 최소 정보만 포함
 */
@RequiredArgsConstructor
@Component
public class JwtTokenProvider {

    private static final String TOKEN_TYPE = "Bearer";

    private static final String ACCESS_TOKEN_TYPE = "access";
    private static final String REFRESH_TOKEN_TYPE = "refresh";

    private final JwtProperties jwtProperties;

    public String createAccessToken(Member member) {
        Date now = now();
        Date expiration = new Date(now.getTime() + jwtProperties.accessTokenExpirationMs());

        return Jwts.builder()
                .subject(member.getUuid().toString())
                .claim("type", ACCESS_TOKEN_TYPE)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(getSecretKey())
                .compact();
    }

    public String createRefreshToken(Member member) {
        Date now = now();
        Date expiration = new Date(now.getTime() + jwtProperties.refreshTokenExpirationMs());

        return Jwts.builder()
                .subject(member.getUuid().toString())
                .claim("type", REFRESH_TOKEN_TYPE)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(getSecretKey())
                .compact();
    }

    private Date now() {
        return new Date(System.currentTimeMillis());
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtProperties.secret().getBytes(StandardCharsets.UTF_8));
    }

    public boolean validateToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isExpiredToken(String token) {
        try {
            getClaims(token);
            return false;
        } catch (ExpiredJwtException e) {
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Claims getClaimsAllowExpired(String token) {
        try {
            return getClaims(token);
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    public UUID getMemberUuid(String token) {
        String subject = getClaims(token).getSubject();
        return UUID.fromString(subject);
    }

    public String getTokenType() {
        return TOKEN_TYPE;
    }

    public long getAccessTokenExpiresIn() {
        return jwtProperties.accessTokenExpirationMs() / 1000;
    }

    public long getRefreshTokenExpiresIn() {
        return jwtProperties.refreshTokenExpirationMs() / 1000;
    }

    public boolean isAccessTokenAllowExpired(String token) {
        String type = getClaimsAllowExpired(token).get("type", String.class);
        return ACCESS_TOKEN_TYPE.equals(type);
    }

    public boolean isRefreshToken(String token) {
        String type = getClaims(token).get("type", String.class);
        return REFRESH_TOKEN_TYPE.equals(type);
    }

}
