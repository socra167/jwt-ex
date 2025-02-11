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
public class CustomAuthenticationFilter extends OncePerRequestFilter { // 필터 역할을 수행하도록 OncePerRequestFilter 구현
	private final Rq rq;
	private final MemberService memberService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		String authorizationHeader = request.getHeader("Authorization");

		if (authorizationHeader == null) {
			filterChain.doFilter(request, response); // 헤더에 인증 정보가 없다면, 다른 동작을 하지 않고 Security가 알아서 처리하도록 Pass
			return; // doFilter()를 하더라도 return을 해야 종료된다.
		}
		if (!authorizationHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}

		String authToken = authorizationHeader.substring("Bearer ".length());
		String[] tokenBits = authToken.split(" ", 2);

		if (tokenBits.length < 2) {
			filterChain.doFilter(request, response);
			return;
		}

		String apiKey = tokenBits[0];
		String accessToken = tokenBits[1];

		Optional<Member> opMemberByAccessToken = memberService.getMemberByAccessToken(accessToken);

		if (opMemberByAccessToken.isEmpty()) {
			// Access Token 만료 시 재발급
			Optional<Member> opmMemberByApiKey = memberService.findByApiKey(apiKey);

			if (opmMemberByApiKey.isEmpty()) { // 잘못된 API Key
				filterChain.doFilter(request, response);
				return;
			}

			String newAuthToken = memberService.getAuthToken(opmMemberByApiKey.get());
			response.addHeader("Authorization", "Bearer " + newAuthToken); // 응답에 새로운 Token 추가

			Member actor = opmMemberByApiKey.get();
			rq.setLogin(actor);

			filterChain.doFilter(request, response);
			return;
		}

		Member actor = opMemberByAccessToken.get();
		rq.setLogin(actor); // user1이 로그인했다고 security에게 알려주면 security는 user1로 인식

		filterChain.doFilter(request, response); // 다음 필터, 없다면 컨트롤러 등으로 넘어간다
	}
}
