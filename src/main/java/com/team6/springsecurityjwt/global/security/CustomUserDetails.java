package com.team6.springsecurityjwt.global.security;

import com.team6.springsecurityjwt.member.entity.Member;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Getter
public class CustomUserDetails implements UserDetails {

    private final Long memberId;
    private final UUID uuid;
    private final String email;
    private final String nickname;
    private final String password;

    public CustomUserDetails(Member member) {
        this.memberId = member.getId();
        this.uuid = member.getUuid();
        this.email = member.getEmail();
        this.nickname = member.getNickname();
        this.password = member.getPasswordHash();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }
}