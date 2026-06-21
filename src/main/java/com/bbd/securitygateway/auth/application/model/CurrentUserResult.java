package com.bbd.securitygateway.auth.application.model;

/*
 Gateway 기준 현재 요청 사용자의 인증 상태를
 application 계층에서 표현하기 위한 결과 모델.

 이 객체는 웹 응답 DTO가 아니다.
 따라서 JSON 응답 형태나 Controller 관심사를 포함하지 않는다.

 역할:
 - GetCurrentUserUseCase의 반환 모델
 - Gateway가 확인한 현재 요청의 로그인 여부 표현
 - Keycloak/OIDC에서 얻은 기본 사용자 정보 표현

 현재 /api/auth/me의 외부 응답 필드도 이 모델과 완전히 같다.
 별도 CurrentUserResponse를 두면 같은 필드를 한 번 더 복사하는 매핑만 생기므로,
 이 단순 조회 슬라이스에서는 이 결과 모델을 그대로 JSON 응답으로 사용한다.

 단, 나중에 외부 응답 스키마가 application 결과 모델과 달라지거나
 웹 응답 전용 필드/포맷이 필요해지면 adapter.in.web 전용 Response DTO를 다시 분리한다.

 이 모델은 ERP 사용자 등록 여부, role, tenancyType, status, permission을 판단하지 않는다.

 해당 ERP 인가 정보는 각 MSA가 Access Token을 직접 검증한 뒤,
 JWT sub를 기준으로 Redis UserSnapshot을 조회해서 판단한다.

 Gateway는 하위 MSA 호출 시 Access Token Relay를 통해
 Authorization: Bearer <access-token>을 전달한다.
 */
public record CurrentUserResult(

        // Gateway 세션 / Spring Security 기준 인증 여부.
        boolean authenticated,

        /*
         Keycloak 사용자의 고유 식별자.
         OIDC sub claim 값이다.

         Gateway에서는 현재 로그인 사용자의 기본 식별 정보로만 사용한다.
         각 MSA에서는 Access Token 검증 후 JWT sub를 꺼내
         Redis UserSnapshot 조회 기준으로 사용한다.
         */
        String keycloakSub,

        /*
         Keycloak/OIDC의 로그인 식별자.
         보통 preferred_username claim에서 가져온다.

         현재는 사번처럼 보일 수 있지만,
         로그인 정책 변경에 따라 이메일, 계정명 등으로 바뀔 수 있다.

         따라서 ERP 사용자 매핑이나 Redis UserSnapshot 조회의 최종 기준으로 사용하지 않는다.
         최종 사용자 식별 기준은 Keycloak sub이다.
         */
        String username,

        /*
         Keycloak/OIDC claim에서 얻은 사용자 기본 정보.
         이 값들은 Gateway의 로그인 상태 응답이나 화면 표시용으로 사용할 수 있다.
         ERP 인가 판단 기준으로 사용하지 않는다.
         */
        String employeeNumber,
        String displayName,
        String email,
        String position,

        // 현재 로그인 상태를 설명하는 메시지.
        String message
) {

    /*
     인증되지 않은 사용자 상태를 표현하는 정적 팩토리 메서드.
     Spring Security 기준 인증되지 않았으므로
     사용자 기본 정보는 모두 null이다.
     */
    public static CurrentUserResult unauthenticated() {
        return new CurrentUserResult(
                false,
                null,
                null,
                null,
                null,
                null,
                null,
                "로그인이 필요합니다."
        );
    }

    /*
     인증된 사용자 상태를 표현하는 정적 팩토리 메서드.

     Gateway는 AuthPrincipal에 들어 있는 Keycloak/OIDC 기본 정보만 사용한다.
     이 정보는 웹 OIDC 세션 사용자와 모바일 Bearer JWT 사용자 모두에 대해 동일하게 표현된다.
     User Service 기준 role, tenancy, status, permission은 여기서 판단하지 않는다.

     실제 ERP 인가는 각 MSA가 Access Token을 검증한 뒤,
     JWT sub 기준으로 Redis UserSnapshot을 조회해서 판단한다.
     */
    public static CurrentUserResult authenticated(AuthPrincipal principal) {
        return new CurrentUserResult(
                true,
                principal.keycloakSub(),
                principal.username(),
                principal.employeeNumber(),
                principal.displayName(),
                principal.email(),
                principal.position(),
                "로그인된 사용자입니다."
        );
    }
}
