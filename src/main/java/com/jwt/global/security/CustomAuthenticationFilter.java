package com.jwt.global.security;

import java.io.IOException;
import java.util.Optional;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jwt.domain.member.member.entity.Member;
import com.jwt.domain.member.member.service.MemberService;
import com.jwt.global.Rq;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component // 컴포넌트 스캔 적용
public class CustomAuthenticationFilter extends OncePerRequestFilter {
	public static final String AUTHORIZATION = "Authorization";
	public static final String ACCESS_TOKEN = "accessToken";
	public static final String BEARER = "Bearer ";
	public static final String API_KEY = "apiKey";
	private final Rq rq;
	private final MemberService memberService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

		AuthToken tokens = getAuthTokenFromRequest();

		if (tokens == null) {
			filterChain.doFilter(request, response);
			return;
		}

		// 재발급 코드
		Member actor = getMemberByAccessToken(tokens.accessToken(), tokens.apiKey());
		if (actor == null) {
			filterChain.doFilter(request, response);
			return;
		}
		rq.setLogin(actor);

		filterChain.doFilter(request, response);
	}

	private boolean isAuthorizationHeader() {
		return Optional.ofNullable(rq.getHeader(AUTHORIZATION))
			.filter(s -> s.startsWith(BEARER))
			.isPresent();
	}

	record AuthToken(String apiKey, String accessToken) {
	}

	private AuthToken getAuthTokenFromRequest() {

		if (isAuthorizationHeader()) {

			String authorizationHeader = rq.getHeader(AUTHORIZATION);
			String authToken = authorizationHeader.substring(BEARER.length());

			String[] tokenBits = authToken.split(" ", 2);

			if (tokenBits.length < 2) {
				return null;
			}

			return new AuthToken(tokenBits[0], tokenBits[1]);
		}

		String accessToken = rq.getValueFromCookie(ACCESS_TOKEN);
		String apiKey = rq.getValueFromCookie(API_KEY);

		if (accessToken == null || apiKey == null) {
			return null;
		}

		return new AuthToken(apiKey, accessToken);

	}

	private Member getMemberByAccessToken(String accessToken, String apiKey) {

		Optional<Member> opMemberByAccessToken = memberService.getMemberByAccessToken(accessToken);

		if (opMemberByAccessToken.isEmpty()) {
			Optional<Member> opMemberByApiKey = memberService.findByApiKey(apiKey);

			if (opMemberByApiKey.isEmpty()) {
				return null;
			}

			refreshAccessToken(opMemberByApiKey.get());
			return opMemberByApiKey.get();
		}

		return opMemberByAccessToken.get();
	}

	private void refreshAccessToken(Member member) {
		String newAccessToken = memberService.genAccessToken(member);
		rq.setHeader(AUTHORIZATION, BEARER + newAccessToken);
		rq.addCookie(ACCESS_TOKEN, newAccessToken);
	}
}
