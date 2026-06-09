package com.bbd.securitygateway.auth.adapter.in.web.response;

import com.bbd.securitygateway.auth.application.model.CurrentUserResult;

/*
 /api/auth/me 응답 DTO.

 Gateway 기준 현재 브라우저 사용자의 세션 로그인 상태와
 Keycloak/OIDC 기본 사용자 정보를 클라이언트에 내려준다.

 해당 판단은 각 MSA가 Access Token을 직접 검증한 뒤,
 JWT sub를 기준으로 Redis UserSnapshot을 조회해서 수행한다.

 Gateway는 하위 MSA 호출 시 Access Token Relay를 통해
 Authorization: Bearer <access-token>을 전달한다.
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

         이 값은 /api/auth/me 응답에서 현재 로그인 사용자를 식별하기 위한
         기본 정보로 내려간다.

         다만 Gateway가 이 값을 하위 MSA에 직접 헤더로 전달하지는 않는다.
         각 MSA는 Gateway가 Relay한 Access Token을 직접 검증한 뒤,
         JWT sub 값을 Redis UserSnapshot 조회 기준으로 사용한다.
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

     application 계층의 CurrentUserResult를 그대로 외부 응답으로 노출하지 않고,
     adapter.in.web 계층의 응답 모델로 변환한다.
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