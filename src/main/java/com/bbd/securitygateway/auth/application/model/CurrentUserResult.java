package com.bbd.securitygateway.auth.application.model;

import com.bbd.securitygateway.auth.domain.User;

/*
 현재 요청 사용자의 인증 상태와 ERP 서비스 이용 상태를
 application 계층에서 표현하기 위한 결과 모델.

 이 객체는 웹 응답 DTO가 아니다.
 따라서 JSON 응답 형태나 Controller 관심사를 포함하지 않는다.

 역할:
 - GetCurrentUserUseCase의 반환 모델
 - 인증 여부, 서비스 사용자 여부, User Snapshot 정보를 application 계층에서 표현
 - adapter.in.web 계층에서 CurrentUserResponse로 변환됨
 */
public record CurrentUserResult(
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
     로그인하지 않은 사용자 상태.
     */
    public static CurrentUserResult unauthenticated() {
        return new CurrentUserResult(
                false,
                false,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
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
     Keycloak 로그인은 되었지만,
     User Service에 ERP 사용자로 등록되지 않은 상태.

     이 경우 User Snapshot이 없으므로 OIDC claim에서 얻은 값을 사용한다.
     */
    public static CurrentUserResult notServiceUser(
            String keycloakSub,
            String username,
            String employeeNumber,
            String displayName,
            String email,
            String position
    ) {
        return new CurrentUserResult(
                true,
                false,
                "NONE",
                keycloakSub,
                username,
                employeeNumber,
                displayName,
                email,
                position,
                null,
                null,
                null,
                null,
                null,
                null,
                "BBD ERP 사용 신청이 필요합니다."
        );
    }

    /*
     ERP 서비스 이용 상태가 INACTIVE인 사용자.
     */
    public static CurrentUserResult inactive(String username, User user) {
        return new CurrentUserResult(
                true,
                false,
                null,
                user.keycloakSub(),
                username,
                user.employeeNumber(),
                user.name(),
                user.email(),
                user.position(),
                user.userId(),
                user.role(),
                user.tenancyType(),
                user.tenancyName(),
                user.status().name(),
                user.version(),
                "BBD ERP 사용이 비활성화된 사용자입니다."
        );
    }

    /*
     ERP 서비스 이용 상태가 PENDING인 사용자.
     */
    public static CurrentUserResult pending(String username, User user) {
        return new CurrentUserResult(
                true,
                false,
                "PENDING",
                user.keycloakSub(),
                username,
                user.employeeNumber(),
                user.name(),
                user.email(),
                user.position(),
                user.userId(),
                user.role(),
                user.tenancyType(),
                user.tenancyName(),
                user.status().name(),
                user.version(),
                "BBD ERP 사용 승인 대기 중입니다."
        );
    }

    /*
     ERP 서비스 이용 상태가 ACTIVE인 사용자.
     */
    public static CurrentUserResult active(String username, User user) {
        return new CurrentUserResult(
                true,
                true,
                null,
                user.keycloakSub(),
                username,
                user.employeeNumber(),
                user.name(),
                user.email(),
                user.position(),
                user.userId(),
                user.role(),
                user.tenancyType(),
                user.tenancyName(),
                user.status().name(),
                user.version(),
                "BBD ERP 사용 가능"
        );
    }
}