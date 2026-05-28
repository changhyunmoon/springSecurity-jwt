package com.team6.springsecurityjwt.global.auth.service;

import com.team6.springsecurityjwt.global.auth.entity.RefreshToken;
import com.team6.springsecurityjwt.global.auth.repository.RefreshTokenRepository;
import com.team6.springsecurityjwt.global.security.jwt.JwtProperties;
import com.team6.springsecurityjwt.member.entity.Member;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;

    @Transactional
    public void saveOrUpdate(Member member, String refreshToken) {
        String tokenHash = hash(refreshToken);
        LocalDateTime expiresAt = LocalDateTime.now()
                .plusSeconds(jwtProperties.refreshTokenExpirationMs() / 1000);

        refreshTokenRepository.findByMember(member)
                .ifPresentOrElse(
                        existingToken -> existingToken.updateToken(tokenHash, expiresAt),
                        () -> refreshTokenRepository.save(
                                RefreshToken.create(member, tokenHash, expiresAt)
                        )
                );
    }

    public void validateStoredToken(Member member, String refreshToken) {
        RefreshToken storedToken = refreshTokenRepository.findByMember(member)
                .orElseThrow(() -> new IllegalArgumentException("Refresh Token을 찾을 수 없습니다."));

        if (storedToken.isExpired()) {
            throw new IllegalArgumentException("만료된 Refresh Token입니다.");
        }

        String tokenHash = hash(refreshToken);

        if (!storedToken.getTokenHash().equals(tokenHash)) {
            throw new IllegalArgumentException("유효하지 않은 Refresh Token입니다.");
        }
    }

    @Transactional
    public void deleteByMember(Member member) {
        refreshTokenRepository.deleteByMember(member);
    }

    private String hash(String token) {
        return DigestUtils.sha256Hex(token);
    }

}