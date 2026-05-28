package com.team6.springsecurityjwt.global.security.jwt;

import com.team6.springsecurityjwt.global.auth.service.RefreshTokenService;
import com.team6.springsecurityjwt.global.security.CustomUserDetails;
import com.team6.springsecurityjwt.member.entity.Member;
import com.team6.springsecurityjwt.member.entity.MemberStatus;
import com.team6.springsecurityjwt.member.repository.MemberRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtTokenResolver jwtTokenResolver;
    private final TokenInjector tokenInjector;
    private final MemberRepository memberRepository;
    private final RefreshTokenService refreshTokenService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String token = jwtTokenResolver.resolveAccessToken(request).orElse(null);

        if (token != null) {
            authenticateWithAccessToken(request, response, token);
        }

        filterChain.doFilter(request, response);
    }

    private void authenticateWithAccessToken(
            HttpServletRequest request,
            HttpServletResponse response,
            String accessToken
    ) {
        try {
            if (!jwtTokenProvider.isAccessTokenAllowExpired(accessToken)) {
                return;
            }

            if (jwtTokenProvider.validateToken(accessToken)) {
                authenticate(accessToken, request);
                return;
            }

            if (jwtTokenProvider.isExpiredToken(accessToken)) {
                reissueTokenAndAuthenticate(request, response);
            }
        } catch (RuntimeException e) {
            SecurityContextHolder.clearContext();
        }
    }

    private void reissueTokenAndAuthenticate(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String refreshToken = jwtTokenResolver.resolveRefreshToken(request).orElse(null);

        if (refreshToken == null
                || !jwtTokenProvider.validateToken(refreshToken)
                || !jwtTokenProvider.isRefreshToken(refreshToken)) {
            return;
        }

        UUID memberUuid = jwtTokenProvider.getMemberUuid(refreshToken);
        Member member = memberRepository.findByUuid(memberUuid)
                .orElse(null);

        if (member == null || !isActiveMember(member)) {
            return;
        }

        refreshTokenService.validateStoredToken(member, refreshToken);

        String newAccessToken = jwtTokenProvider.createAccessToken(member);
        String newRefreshToken = jwtTokenProvider.createRefreshToken(member);

        refreshTokenService.saveOrUpdate(member, newRefreshToken);

        tokenInjector.injectAccessToken(newAccessToken, response);
        tokenInjector.injectRefreshToken(newRefreshToken, response);

        setAuthentication(member, request);
    }

    private void authenticate(String accessToken, HttpServletRequest request) {
        UUID memberUuid = jwtTokenProvider.getMemberUuid(accessToken);

        memberRepository.findByUuid(memberUuid)
                .filter(this::isActiveMember)
                .ifPresent(member -> setAuthentication(member, request));
    }

    private boolean isActiveMember(Member member) {
        return member.getStatus() == MemberStatus.ACTIVE;
    }

    private void setAuthentication(Member member, HttpServletRequest request) {
        CustomUserDetails userDetails = new CustomUserDetails(member);

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
