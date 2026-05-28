package com.team6.springsecurityjwt.member.service;


import com.team6.springsecurityjwt.member.dto.request.MemberSignupRequest;
import com.team6.springsecurityjwt.member.dto.response.MemberSignupResponse;
import com.team6.springsecurityjwt.member.entity.Member;
import com.team6.springsecurityjwt.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public MemberSignupResponse signup(MemberSignupRequest request) {
        if (memberRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        String passwordHash = passwordEncoder.encode(request.password());

        Member member = Member.create(
                request.email(),
                passwordHash,
                request.nickname()
        );

        Member savedMember = memberRepository.save(member);

        return new MemberSignupResponse(
                savedMember.getUuid(),
                savedMember.getEmail(),
                savedMember.getNickname()
        );
    }
}