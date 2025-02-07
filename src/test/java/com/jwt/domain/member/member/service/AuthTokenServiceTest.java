package com.jwt.domain.member.member.service;

import static org.assertj.core.api.Assertions.*;

import java.security.Key;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import com.jwt.domain.member.member.entity.Member;
import com.jwt.standard.Ut;

import io.jsonwebtoken.security.Keys;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class AuthTokenServiceTest {
	@Autowired
	private AuthTokenService authTokenService;
	@Autowired
	private MemberService memberService;

	@Test
	@DisplayName("AuthTokenService 생성")
	void init() {
		assertThat(authTokenService).isNotNull();
	}

	@Test
	@DisplayName("JWT 생성")
	void createToken() {
		// 토큰 만료기간 : 1년
		int expireSeconds = 60 * 60 * 24 * 365;

		// 토큰 시크릿 키
		Key secretKey = Keys.hmacShaKeyFor("abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890".getBytes());

		String jwt = Ut.Jwt.createToken(secretKey, expireSeconds, Map.of("name", "john", "age", 23 ));

		assertThat(jwt).isNotBlank();
		System.out.println("jwt = " + jwt);
	}


	@Test
	@DisplayName("Access Token 생성")
	void accessToken() {
		// Access Token이라고 불리는 JWT (뭔가를 접근하기 위한 토큰, 인증 정보를 담고 있는 토큰)
		Member member = memberService.findByUsername("user1").get();
		String accessToken = authTokenService.genAccessToken(member);

		assertThat(accessToken).isNotBlank();
		System.out.println("accessToken = " + accessToken);
	}
}
