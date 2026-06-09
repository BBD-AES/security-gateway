package com.bbd.securitygateway.auth.adapter.in.web.response;

import com.bbd.securitygateway.auth.application.model.CurrentUserResult;

/*
 /api/auth/me 응답 DTO.

 Gateway 기준 현재 브라우저 사용자의 세션 로그인 상태와
 Keycloak/OIDC 기본 사용자 정보를 클라이언트에 내려준다.

 이 응답은 ERP 사용자 등록 여부, ERP 사용 가능 여부,
 role, tenancy, status, permission 같은 인가 정보를 표현하지 않는다.

 해당 판단은 각 MSA의 경량 인가 프레임워크가
 Redis의 UserSnapshot을 조회해서 수행한다.

 이 클래스는 adapter.in.web 계층에 속한다.
 따라서 application/service에서 직접 사용하면 안 된다.
 */
public record CurrentUserResponse(

        /*
         Gateway 세션 기준 로그인 여부.

         false이면 Spring Security 기준 인증되지 않은 사용자이다.
         이 경우 아래 사용자 정보는 모두 null일 수 있다.
         */
        boolean authenticated,

        /*
         Keycloak 사용자의 고유 식별자.

         OIDC sub claim 값이다.
         각 MSA가 UserSnapshot을 조회할 때 사용할 수 있도록
         Gateway가 하위 요청에 전달할 기준 식별자이기도 하다.
         */
        String keycloakSub,

        /*
         Keycloak/OIDC의 로그인 식별자.

         보통 preferred_username claim에서 가져온다.
         현재는 사번처럼 보일 수 있지만,
         ERP 사용자 매핑의 최종 기준은 keycloakSub이다.
         */
        String username,

        /*
         Keycloak/OIDC claim에서 얻은 사용자 기본 정보.

         이 값들은 화면 표시나 초기 상태 확인용이며,
         ERP 인가 판단 기준으로 사용하지 않는다.
         */
        String employeeNumber,
        String displayName,
        String email,
        String position,

        /*
         현재 로그인 상태 안내 메시지.
         */
        String message
) {

    /*
     application 결과 모델을 웹 응답 DTO로 변환한다.
     */
    public static CurrentUserResponse from(CurrentUserResult result) {
        return new CurrentUserResponse(
                result.authenticated(),
                result.keycloakSub(),
                result.username(),
                result.employeeNumber(),
                result.displayName(),
                result.email(),
                result.position(),
                result.message()
        );
    }
}