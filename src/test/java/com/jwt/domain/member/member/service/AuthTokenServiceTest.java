package com.jwt.domain.member.member.service;

import static org.assertj.core.api.Assertions.*;

import java.util.Map;

import javax.crypto.SecretKey;

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

	// 토큰 시크릿 키
	SecretKey secretKey = Keys.hmacShaKeyFor(
		"abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890".getBytes());

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

		Map<String, Object> originPayload = Map.of("name", "john", "age", 23);
		String jwtStr = Ut.Jwt.createToken(secretKey, expireSeconds, originPayload);
		assertThat(jwtStr).isNotBlank();

		// 파싱하는 과정에서, JWT가 누구에게나 공개되어 있어 위변조가 있을 수 있다. 또 유효기간이 지나면 JWT는 동작하면 안된다.
		// -> parse() 과정을 살펴보자 - ExpiredJwtException, MalformedJwtException, SignatureException, SecurityException, IllegalArgumentException ...
		// 메서드 안에 이미 구현되어 있다. 잘못된 JWT가 들어오면 이미 데이터를 꺼내오기 전에 예외가 발생한다
		Map<String, Object> parsedPayload = Ut.Jwt.getPayload(secretKey, jwtStr);
		assertThat(parsedPayload).containsAllEntriesOf(originPayload); // issuedAt, expiration가 추가되어서 완전히 일치하진 않는다
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

	@Test
	@DisplayName("JWT valid check")
	void checkValid() {
		Member member = memberService.findByUsername("user1").get();
		String accessToken = authTokenService.genAccessToken(member);
		boolean isValid = Ut.Jwt.isValidToken(secretKey, accessToken);
		assertThat(isValid).isTrue();

		Map<String, Object> parsedPayload = Ut.Jwt.getPayload(secretKey, accessToken);

		assertThat(parsedPayload).containsAllEntriesOf(
			Map.of("id", member.getId(), "username", member.getUsername())
		);
	}
}
