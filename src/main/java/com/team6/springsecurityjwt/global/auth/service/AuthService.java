package com.team6.springsecurityjwt.global.auth.service;

import com.team6.springsecurityjwt.global.auth.dto.request.LoginRequest;
import com.team6.springsecurityjwt.global.auth.dto.response.TokenResult;
import com.team6.springsecurityjwt.global.security.CustomUserDetails;
import com.team6.springsecurityjwt.global.security.jwt.JwtTokenProvider;
import com.team6.springsecurityjwt.member.entity.Member;
import com.team6.springsecurityjwt.member.entity.MemberStatus;
import com.team6.springsecurityjwt.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public TokenResult login(LoginRequest request) {
        Member member = memberRepository.findByEmail(request.email())
                .orElseThrow(() -> new IllegalArgumentException("이메일 또는 비밀번호가 올바르지 않습니다."));

        if (!passwordEncoder.matches(request.password(), member.getPasswordHash())) {
            throw new IllegalArgumentException("이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        if (member.getStatus() != MemberStatus.ACTIVE) {
            throw new IllegalArgumentException("로그인할 수 없는 회원 상태입니다.");
        }

        String accessToken = jwtTokenProvider.createAccessToken(member);
        String refreshToken = jwtTokenProvider.createRefreshToken(member);

        refreshTokenService.saveOrUpdate(member, refreshToken);

        return new TokenResult(
                accessToken,
                refreshToken,
                jwtTokenProvider.getTokenType(),
                jwtTokenProvider.getAccessTokenExpiresIn()
        );
    }

    @Transactional
    public void logout(CustomUserDetails userDetails) {
        Member member = memberRepository.findById(userDetails.getMemberId())
                .orElseThrow(() -> new IllegalArgumentException("회원을 찾을 수 없습니다."));

        refreshTokenService.deleteByMember(member);
    }
}
