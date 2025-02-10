package com.jwt.domain.member.member.entity;

import org.springframework.data.jpa.domain.support.AuditingEntityListener;

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
}