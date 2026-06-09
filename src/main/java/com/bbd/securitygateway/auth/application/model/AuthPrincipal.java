package com.bbd.securitygateway.auth.application.model;

/*
 Spring Security Authentication에서 추출한 현재 인증 사용자 정보.

 이 객체는 application 계층이 Spring Security의 Authentication, OidcUser 같은
 프레임워크 타입에 직접 의존하지 않도록 중간에서 사용하는 모델이다.

 즉, adapter.in.web 또는 adapter.in.security 계층에서
 Authentication/OidcUser를 읽어 AuthPrincipal로 변환한 뒤
 application use case에 전달한다.

 이 객체는 Gateway 세션 인증 결과만 표현한다.
 User Service 기준 userId, role, tenancyType, status, permission 같은
 ERP 인가 정보는 포함하지 않는다.

 해당 ERP 인가 정보는 각 MSA가 Access Token을 직접 검증한 뒤,
 JWT sub를 기준으로 Redis UserSnapshot을 조회해서 판단한다.

 Gateway는 /api/auth/me에서 현재 브라우저 사용자의 세션 로그인 상태와
 Keycloak/OIDC 기본 사용자 정보만 제공한다.
 */
public record AuthPrincipal(
        boolean authenticated,

        /*
         Keycloak 사용자 고유 식별자.

         OIDC subject claim에서 가져온다.

         username, employeeNumber는 정책에 따라 바뀔 수 있지만,
         keycloakSub는 Keycloak Realm 내 사용자를 식별하는 안정적인 고유값이다.

         Gateway에서는 /api/auth/me 응답에 이 값을 포함할 수 있다.
         각 MSA에서는 Access Token 검증 후 JWT sub를 꺼내
         Redis UserSnapshot 조회 기준으로 사용한다.
         */
        String keycloakSub,

        /*
         로그인 식별자.

         보통 OIDC preferred_username claim에서 가져온다.

         현재 프로젝트에서는 사번 로그인이라 HQ001, BR001 같은 값이 들어갈 수 있지만,
         나중에 이메일 로그인, 별도 로그인 ID, AD/LDAP 계정명 등을 허용하면
         employeeNumber와 달라질 수 있다.

         따라서 username은 ERP 사용자 매핑이나 UserSnapshot 조회의 최종 기준으로 사용하지 않는다.

         예:
         - username = HQ001
         - username = csyoon
         - username = csyoon@bbd.com
         */
        String username,

        /*
         사번
         현재 프로젝트에서는 로그인 ID와 같을 수 있지만,
         정책 변경에 따라 username과 달라질 수 있으므로 별도 필드로 둔다.
         */
        String employeeNumber,

        // 사용자 표시 이름
        String displayName,

        // 사용자 이메일
        String email,

        // 사용자 직책 또는 직무 정보
        String position
) {

    /*
     인증되지 않은 사용자를 표현하는 정적 팩토리 메서드.

     즉, 아래처럼 생성자를 직접 호출하는 대신
     new AuthPrincipal(false, null, null, null, null, null, null)

     다음처럼 의미가 드러나는 메서드로 생성한다.
     AuthPrincipal.unauthenticated()

     이렇게 하면 호출하는 코드에서
     "인증되지 않은 사용자 객체를 만드는구나"를 더 명확하게 알 수 있다.

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

    /*
     인증된 사용자를 표현하는 정적 팩토리 메서드.

     생성자를 직접 호출하면 첫 번째 인자인 true가 무엇을 의미하는지
     호출하는 코드만 보고는 명확하지 않을 수 있다.

     예:
     new AuthPrincipal(true, keycloakSub, username, employeeNumber, displayName, email, position)

     대신 아래처럼 사용하면 현재 객체가
     "인증된 사용자 정보"를 표현한다는 의도가 명확해진다.

     AuthPrincipal.authenticated(
         keycloakSub,
         username,
         employeeNumber,
         displayName,
         email,
         position
     )

     이 메서드는 adapter 계층에서
     Spring Security Authentication/OidcUser를 읽어
     application 계층이 사용할 수 있는 AuthPrincipal로 변환할 때 사용한다.
     */
    public static AuthPrincipal authenticated(
            String keycloakSub,
            String username,
            String employeeNumber,
            String displayName,
            String email,
            String position
    ) {
        return new AuthPrincipal(
                true,
                keycloakSub,
                username,
                employeeNumber,
                displayName,
                email,
                position
        );
    }
}