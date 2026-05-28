package com.team6.springsecurityjwt.member.entity;

import com.team6.springsecurityjwt.global.domain.BaseTimeEntity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;


@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Entity
public class Member extends BaseTimeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, unique = true, updatable = false, length = 36)
    private UUID uuid;

    @Column(nullable = false, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(nullable = false, length = 50)
    private String nickname;

    @Column(name = "profile_image_s3_key")
    private String profileImageS3Key;

    @Column(name = "status_message", length = 100)
    private String statusMessage;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private MemberStatus status;

    public static Member create(
            String email,
            String passwordHash,
            String nickname
    ) {
        return Member.builder()
                .uuid(UUID.randomUUID())
                .email(email)
                .passwordHash(passwordHash)
                .nickname(nickname)
                .status(MemberStatus.ACTIVE)
                .build();
    }


}