package com.team6.springsecurityjwt.member.dto.response;

import java.util.UUID;

public record MemberSignupResponse(
        UUID uuid,
        String email,
        String nickname
) {
}