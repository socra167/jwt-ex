package com.jwt.domain.member.member.service;

import static org.assertj.core.api.Assertions.*;

import java.security.Key;
import java.util.Date;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class AuthTokenServiceTest {
	@Autowired
	private AuthTokenService authTokenService;

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

		// 정보
		Claims claims = Jwts.claims()
			.add("name", "Paul")
			.add("age", 23)
			.build();
		Date issuedAt = new Date();
		Date expiration = new Date(issuedAt.getTime() + 1000L * expireSeconds);

		// JWT를 생성(공식문서 참고)
		String jwt = Jwts.builder()
			.setClaims(claims)
			.setIssuedAt(issuedAt)
			.setExpiration(expiration)
			.signWith(secretKey, SignatureAlgorithm.HS256)
			.compact();
		assertThat(jwt).isNotBlank();
		System.out.println("jwt = " + jwt);
	}
}
