package com.jwt.domain.member.member.entity;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.jwt.global.entity.BaseTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder // 부모 클래스까지 빌더로 사용할 수 있다(부모 클래스에도 @SuperBuilder를 적용해줘야 한다)
@EntityListeners(AuditingEntityListener.class)
public class Member extends BaseTime {

    @Column(length = 100, unique = true)
    private String username;
    @Column(length = 100)
    private String password;
    @Column(length = 100, unique = true)
    private String apiKey;
    @Column(length = 100)
    private String nickname;

    public boolean isAdmin() {
        return username.equals("admin");
    }

    public Collection<? extends GrantedAuthority> getAutorities() {
        // new SimpleGrantedAuthority("ROLE_USER"); 원래는 이런 형식인데, 우리는 STRING으로 관리하고 최종적으로 줄 떄만 이렇게 처리해서 주도록 해보자
        return getMemberAuthoritiesAsString()
            .stream()
            .map(SimpleGrantedAuthority::new) // Security에서 사용하는 형식으로
            .toList();
    }

    public List<String> getMemberAuthoritiesAsString() {
        List<String> authorities = new ArrayList<>();

        if (isAdmin()) {
            authorities.add("ADMIN_ACT");
        }

        return authorities;
    }
}