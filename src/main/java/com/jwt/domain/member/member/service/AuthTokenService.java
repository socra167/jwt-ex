package com.jwt.domain.member.member.service;

import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.jwt.domain.member.member.entity.Member;
import com.jwt.standard.Ut;

import io.jsonwebtoken.security.Keys;

@Service
public class AuthTokenService {

	public String genAccessToken(Member member) {
		int expireSeconds = 60 * 60 * 24 * 365;
		return Ut.Jwt.createToken(
			Keys.hmacShaKeyFor("abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890".getBytes()),
			expireSeconds,
			Map.of("id", member.getId(), "username", member.getUsername())
		);
	}

	public Map<String, Object> getPayload(SecretKey secretKey, String token) {
		Map<String, Object> payload = Ut.Jwt.getPayload(secretKey, token);

		if (payload == null) return null;

		Number idNo = (Number)payload.get("id");
		long id = idNo.longValue();

		String username = (String)payload.get("username");

		return Map.of("id", id, "username", username);
	}
}
