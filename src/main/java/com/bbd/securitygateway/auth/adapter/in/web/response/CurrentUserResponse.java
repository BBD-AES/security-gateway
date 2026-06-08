package com.bbd.securitygateway.auth.adapter.in.web.response;

import com.bbd.securitygateway.auth.application.model.CurrentUserResult;

/*
 /api/auth/me 응답 DTO.

 application 계층의 CurrentUserResult를
 웹 응답 형태로 변환해서 클라이언트에 내려준다.

 이 클래스는 adapter.in.web 계층에 속한다.
 따라서 application/service에서 직접 사용하면 안 된다.
 */
public record CurrentUserResponse(
        boolean authenticated,
        boolean serviceUser,
        String accessRequestStatus,

        String keycloakSub,
        String username,
        String employeeNumber,
        String displayName,
        String email,
        String position,

        Long userId,
        String role,
        String tenancyType,
        String tenancyName,
        String status,
        Long version,

        String message
) {

    /*
     application 결과 모델을 웹 응답 DTO로 변환한다.
     */
    public static CurrentUserResponse from(CurrentUserResult result) {
        return new CurrentUserResponse(
                result.authenticated(),
                result.serviceUser(),
                result.accessRequestStatus(),
                result.keycloakSub(),
                result.username(),
                result.employeeNumber(),
                result.displayName(),
                result.email(),
                result.position(),
                result.userId(),
                result.role(),
                result.tenancyType(),
                result.tenancyName(),
                result.status(),
                result.version(),
                result.message()
        );
    }
}