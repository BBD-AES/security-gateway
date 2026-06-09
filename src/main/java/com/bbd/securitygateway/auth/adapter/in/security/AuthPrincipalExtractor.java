package com.bbd.securitygateway.auth.adapter.in.security;

import com.bbd.securitygateway.auth.application.model.AuthPrincipal;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

/*
 Spring Security Authentication을
 application 계층에서 사용하는 AuthPrincipal로 변환하는 Adapter.

 역할:
 - 인증되지 않은 요청을 AuthPrincipal.unauthenticated()로 변환한다.
   (Authentication이 null이거나, 인증되지 않았거나, AnonymousAuthenticationToken인 경우)

 - 웹 세션 기반 OIDC 로그인 사용자를 AuthPrincipal.authenticated(...)로 변환한다.
   (oauth2Login 성공 후 principal이 OidcUser이기 때문에 가능하다.)

 사용 위치:
 - AuthController
   (/api/auth/me에서 현재 Gateway 세션 로그인 사용자 정보를
    application use case에 넘길 때 사용)

 현재 Gateway 구조:
 - 브라우저는 Gateway에 JSESSIONID 세션 쿠키로 요청한다.
 - Gateway는 oauth2Login 기반 OIDC 로그인을 처리한다.
 - /api/auth/me는 Gateway 세션 기준 현재 로그인 상태와
   Keycloak/OIDC 기본 사용자 정보를 프론트엔드에 반환한다.

 주의:
 - 이 클래스는 UserSnapshot을 조회하지 않는다.
 - Redis를 조회하지 않는다.
 - role, tenancy, status, permission을 판단하지 않는다.
 - 하위 MSA로 사용자 식별자를 전달하지 않는다.

 최종 인가 구조:
 - Gateway는 Access Token Relay를 통해 하위 MSA에
   Authorization: Bearer <access-token>을 전달한다.
 - 각 MSA는 Access Token을 직접 검증한다.
 - 각 MSA는 JWT sub를 기준으로 Redis UserSnapshot을 먼저 조회하고,
   없으면 User Service를 조회해 Snapshot을 적재한다.
 */
@Component
public class AuthPrincipalExtractor {

    /*
     Spring Security Authentication에서 현재 인증 사용자 정보를 추출한다.

     인증되지 않은 요청이면 AuthPrincipal.unauthenticated()를 반환한다.
     OIDC 로그인 사용자이면 OidcUser claim을 읽어 AuthPrincipal.authenticated(...)를 반환한다.

     이 메서드는 예외를 던지지 않고 unauthenticated로 안전하게 떨어지도록 설계한다.
     이유는 /api/auth/me가 로그인 여부를 프론트엔드에 알려주는 API이기 때문이다.

     즉, 로그인하지 않은 사용자도 /api/auth/me를 호출할 수 있고,
     이 경우 예외가 아니라 authenticated=false 응답으로 처리하는 것이 자연스럽다.
     */
    public AuthPrincipal extract(Authentication authentication) {
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return AuthPrincipal.unauthenticated();
        }

        Object principal = authentication.getPrincipal();

        /*
         웹 세션 기반 OIDC 로그인 성공 시 principal은 OidcUser이다.

         여기서는 Gateway가 /api/auth/me 응답에 내려줄
         최소 인증 사용자 정보만 추출한다.

         추출하는 값:
         - subject: Keycloak 사용자 고유 식별자
         - preferred_username: 로그인 식별자
         - employee_number: 사번 claim
         - name: 표시 이름
         - email: 이메일
         - position: 직책/직무 claim
         */
        if (principal instanceof OidcUser oidcUser) {
            return AuthPrincipal.authenticated(
                    oidcUser.getSubject(),
                    oidcUser.getPreferredUsername(),
                    oidcUser.getClaimAsString("employee_number"),
                    oidcUser.getClaimAsString("name"),
                    oidcUser.getEmail(),
                    oidcUser.getClaimAsString("position")
            );
        }

        /*
         현재 /api/auth/me는 웹 세션 기반 OIDC 로그인 사용자를 대상으로 한다.

         예상하지 않은 principal 타입이면
         Gateway 기준 현재 사용자 정보를 확정할 수 없으므로
         unauthenticated로 처리한다.
         */
        return AuthPrincipal.unauthenticated();
    }
}