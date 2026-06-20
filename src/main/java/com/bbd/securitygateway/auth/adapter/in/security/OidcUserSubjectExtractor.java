package com.bbd.securitygateway.auth.adapter.in.security;

import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import java.util.Optional;

/*
 Spring Security principal에서 Keycloak 사용자 고유값(sub)만 추출하는 Adapter.

 같은 OIDC 사용자 여부를 판단하는 기준은 여러 곳에서 필요하지만,
 실패했을 때의 처리 방식은 호출 위치마다 다르다.
 - /api/auth/me: 인증되지 않은 사용자로 안전하게 처리한다.
 - 로그인 성공 핸들러: 세션 만료 정책과 직결되므로 예외로 실패시킨다.

 그래서 이 클래스는 값 추출만 담당하고, 실패 시맨틱은 호출자가 결정한다.
 */
@Component
public class OidcUserSubjectExtractor {

    public Optional<String> extract(Object principal) {
        if (principal instanceof OidcUser oidcUser) {
            return Optional.ofNullable(oidcUser.getSubject());
        }

        return Optional.empty();
    }
}
