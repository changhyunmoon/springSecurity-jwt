package com.team6.springsecurityjwt.member.controller;

import com.team6.springsecurityjwt.global.security.CustomUserDetails;
import com.team6.springsecurityjwt.member.dto.request.MemberSignupRequest;
import com.team6.springsecurityjwt.member.dto.response.MemberMeResponse;
import com.team6.springsecurityjwt.member.dto.response.MemberSignupResponse;
import com.team6.springsecurityjwt.member.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    //회원가입
    @PostMapping("/signup")
    public ResponseEntity<MemberSignupResponse> signup(
            @Valid @RequestBody MemberSignupRequest request
    ) {
        MemberSignupResponse response = memberService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/me")
    public ResponseEntity<MemberMeResponse> me(
            @AuthenticationPrincipal CustomUserDetails userDetails
    ) {
        MemberMeResponse response = new MemberMeResponse(
                userDetails.getUuid(),
                userDetails.getEmail(),
                userDetails.getNickname()
        );

        return ResponseEntity.ok(response);
    }
}
