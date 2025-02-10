package com.jwt.global.security;

import java.util.List;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.jwt.domain.member.member.entity.Member;
import com.jwt.domain.member.member.repository.MemberRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService { // 스프링 시큐리티가 제공하는 인터페이스를 구현
	private final MemberRepository memberRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// UserDetails 내부를 보면 username, password, authorities를 구해와야 한다
		Member member = memberRepository.findByUsername(username)
			.orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다."));

		return new SecurityUser(member.getId(), member.getUsername(), member.getPassword(), List.of()); // 아직 권한을 만들지 않아 빈 리스트
	}
}
