package com.jwt.domain.member.member.service;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.jwt.domain.member.member.entity.Member;
import com.jwt.standard.Ut;

@Service
public class AuthTokenService {

	@Value("${custom.jwt.secret-key}")
	private String keyString;

	@Value("${custom.jwt.expire-seconds}")
	private int expireSeconds;

	String genAccessToken(Member member) {
		int expireSeconds = 60 * 60 * 24 * 365;
		return Ut.Jwt.createToken(
			keyString,
			expireSeconds,
			Map.of("id", member.getId(), "username", member.getUsername())
		);
	}

	Map<String, Object> getPayload(String keyString, String token) {
		Map<String, Object> payload = Ut.Jwt.getPayload(keyString, token);

		if (payload == null) return null;

		Number idNo = (Number)payload.get("id");
		long id = idNo.longValue();

		String username = (String)payload.get("username");

		return Map.of("id", id, "username", username);
	}
}
