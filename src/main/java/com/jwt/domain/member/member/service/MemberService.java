package com.jwt.domain.member.member.service;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.jwt.domain.member.member.entity.Member;
import com.jwt.domain.member.member.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final AuthTokenService authTokenService;

    public Member join(String username, String password, String nickname) {

        Member member = Member.builder()
                .username(username)
                .password(password)
                .apiKey(username)
                .nickname(nickname)
                .build();

        return memberRepository.save(member);
    }

    public long count() {
        return memberRepository.count();
    }

    public Optional<Member> findByUsername(String username) {
        return memberRepository.findByUsername(username);
    }

    public Optional<Member> findById(long id) {
        return memberRepository.findById(id);
    }

    public Optional<Member> findByApiKey(String apiKey) {
        return memberRepository.findByApiKey(apiKey);
    }

    public String getAuthToken(Member member) {
        // 인증을 위한 토큰은 액세스 토큰으로 쓰다가, API key로 바꿀 수도 있다.
        // 인증 방식이 바뀌어도 유연하게 사용 가능하도록 추상적인 메서드명으로 설정
        return authTokenService.genAccessToken(member);
    }
}