package com.bbd.securitygateway.auth.application.model;

/*
 Spring Security Authentication에서 추출한 현재 인증 사용자 정보.

 이 객체는 application 계층이 Spring Security의 Authentication, OidcUser 같은
 프레임워크 타입에 직접 의존하지 않도록 중간에서 사용하는 모델이다.

 즉, adapter.in.web 또는 adapter.in.security 계층에서
 Authentication/OidcUser를 읽어 AuthPrincipal로 변환한 뒤
 application usecase에 전달한다.
*/

/*
 username: 로그인 식별자

 보통 OIDC preferred_username claim에서 가져온다.

 현재 프로젝트에서는 사번 로그인이라 HQ001, BR001 같은 값이 들어갈 수 있지만,
 나중에 이메일 로그인, 별도 로그인 ID, AD/LDAP 계정명 등을 허용하면
 employeeNumber와 달라질 수 있다.

 따라서 username은 User Service의 ERP 사용자와 연결하는 최종 기준으로 사용하지 않는다.
 ERP 사용자 매핑은 Keycloak의 고유 식별자인 keycloakSub를 우선 사용한다.

 예:
 - username = HQ001
 - username = csyoon
 - username = csyoon@bbd.com
 */

public record AuthPrincipal(
        boolean authenticated,
        String keycloakSub,
        String username,
        String employeeNumber,
        String displayName,
        String email,
        String position
) {

    /*
     로그인하지 않은 사용자 상태를 표현한다.

     예:
     - Authentication이 null인 경우
     - AnonymousAuthenticationToken인 경우
     - 인증되지 않은 요청인 경우
     */
    public static AuthPrincipal unauthenticated() {
        return new AuthPrincipal(
                false,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }
}