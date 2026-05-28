package com.team6.springsecurityjwt.member.dto.response;

import java.util.UUID;

public record MemberMeResponse(
        UUID memberUuid,
        String email,
        String nickname
) {
}
