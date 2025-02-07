package com.jwt.standard;

import java.security.Key;
import java.util.Date;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class Ut {
	public static class Json {
		private static final ObjectMapper objectMapper = new ObjectMapper();

		public static String toString(Object obj) {
			try{
				return objectMapper.writeValueAsString(obj);
			} catch (JsonProcessingException e) {
				throw new RuntimeException(e);
			}
		}
	}

	public static class Jwt {

		public static String createToken(Key secretKey, int expireSeconds, Map<String, Object> claims) {
			Date issuedAt = new Date();
			Date expiration = new Date(issuedAt.getTime() + 1000L * expireSeconds);

			// JWT를 생성(공식문서 참고)
			return Jwts.builder()
				.setExpiration(expiration)
				.signWith(secretKey, SignatureAlgorithm.HS256)
				.compact();
		}
	}
}
