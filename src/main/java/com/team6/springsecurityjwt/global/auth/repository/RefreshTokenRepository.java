package com.team6.springsecurityjwt.global.auth.repository;

import com.team6.springsecurityjwt.global.auth.entity.RefreshToken;
import com.team6.springsecurityjwt.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByMember(Member member);

    void deleteByMember(Member member);
}