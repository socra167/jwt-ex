package com.jwt;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import com.jwt.domain.member.member.service.AuthTokenService;

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
}
