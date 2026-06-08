package com.bbd.securitygateway.auth.adapter.in.web.response;

import com.bbd.securitygateway.auth.domain.User;

/*
 현재 요청 사용자의 인증 상태와 ERP 서비스 이용 상태를
 프론트엔드에 내려주기 위한 /api/auth/me 응답 모델.

 이 객체는 도메인 모델이라기보다는 응답 DTO이다.

 예를 들어 /api/auth/me 응답에서 다음 상태를 표현한다.

 - 아직 로그인하지 않은 사용자
 - Keycloak 로그인은 했지만 User Service 기준 ERP 사용자로 등록되지 않은 사용자
 - User Service에는 존재하지만 ERP 서비스 이용 상태가 INACTIVE인 사용자
 - User Service에는 존재하지만 ERP 서비스 이용 상태가 PENDING인 사용자
 - 정상적으로 BBD ERP를 사용할 수 있는 사용자

 즉, CurrentUserResponse는
 "현재 브라우저 사용자가 지금 우리 서비스에서 어떤 상태인가"를
 프론트엔드가 판단할 수 있도록 내려주는 응답 모델이다.
 */
public record CurrentUserResponse(

        /*
         Keycloak 기준 로그인 여부.

         false이면 아직 로그인하지 않았거나 세션이 만료된 사용자이다.
         true이면 Keycloak 인증은 완료된 사용자이다.
         */
        boolean authenticated,

        /*
         BBD ERP 서비스를 현재 이용할 수 있는 사용자 여부.

         true이면 User Service 기준 ERP 사용자로 등록되어 있고,
         UserStatus가 ACTIVE인 사용자이다.

         false이면 다음 경우일 수 있다.
         - 로그인하지 않음
         - Keycloak 로그인은 했지만 User Service에 ERP 사용자로 등록되지 않음
         - User Service에는 존재하지만 INACTIVE 또는 PENDING 상태임
         */
        boolean serviceUser,

        /*
         서비스 사용 신청 상태.

         Keycloak 로그인은 되었지만 User Service에 ERP 사용자로 등록되지 않은 경우,
         또는 별도의 서비스 사용 신청 흐름이 있는 경우 상태를 표현하기 위한 값이다.

         예:
         - NONE: 아직 사용 신청 없음
         - PENDING: 사용 신청 검토 중
         - REJECTED: 사용 신청 거절
         */
        String accessRequestStatus,

        /*
         Keycloak 사용자의 고유 식별자.

         OIDC ID Token의 sub claim에 해당한다.
         Keycloak 사용자와 User Service의 ERP 사용자를 연결할 때 기준으로 사용한다.
         */
        String keycloakSub,

        /*
         Keycloak 또는 OIDC claim에서 가져온 사용자명.

         보통 preferred_username 값이 들어간다.
         프로젝트 기준으로는 사번 로그인이라면 HQ001, BR001 같은 값이 될 수 있다.
         */
        String username,

        /*
         사번.

         User Service에 등록된 사용자인 경우에는 User Snapshot 기준 값을 내려준다.
         User Service에 등록되지 않은 사용자인 경우에는 OIDC claim 기준 값을 내려줄 수 있다.
         */
        String employeeNumber,

        /*
         화면에 표시할 사용자 이름.
         */
        String displayName,

        /*
         사용자 이메일.
         */
        String email,

        /*
         직책/직무명.

         예:
         - 부장
         - 과장
         - 지점장
         - 구매 담당자

         권한 판단 기준은 아니고, 화면 표시나 사용자 정보 표현에 사용한다.
         */
        String position,

        /*
         User Service users 테이블 기준의 내부 사용자 PK.

         Keycloak에는 있지만 User Service에 ERP 사용자로 등록되지 않은 사용자는 null일 수 있다.
         */
        Long userId,

        /*
         ERP 시스템 권한.

         예:
         - ADMIN
         - HQ_MANAGER
         - HQ_STAFF
         - BRANCH_MANAGER
         - BRANCH_STAFF

         이 값은 Keycloak Access Token의 role claim이 아니라,
         User Service에서 조회했거나 세션/Redis에 캐시된 User Snapshot의 role 값이다.

         실제 도메인별 최종 인가는 Sales/Purchase/Inventory 같은 각 서비스에서 수행한다.
         */
        String role,

        /*
         소속 유형.

         예:
         - HQ
         - BRANCH
         */
        String tenancyType,

        /*
         소속 이름.

         예:
         - 본사
         - 강남 1지점
         */
        String tenancyName,

        /*
         User Service 기준 ERP 사용자 상태.

         예:
         - ACTIVE
         - INACTIVE
         - PENDING

         이 값은 Keycloak 계정 enabled/disabled가 아니라,
         ERP 서비스 내부의 이용 상태이다.
         */
        String status,

        /*
         사용자 정보 버전.

         role, status, tenancy 정보 같은 중요 정보가 변경될 때 증가한다.
         세션이나 Redis에 저장된 User Snapshot의 최신성 확인에 사용할 수 있다.
         */
        Long version,

        /*
         현재 사용자 상태를 프론트엔드에 설명하기 위한 메시지.
         */
        String message
) {

    /*
     로그인하지 않은 사용자 상태를 생성한다.

     예:
     - 브라우저에 세션이 없음
     - 세션이 만료됨
     - 아직 로그인하지 않음
     */
    public static CurrentUserResponse unauthenticated() {
        return new CurrentUserResponse(
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
     User Service에 ERP 사용자로 등록되지 않은 상태를 생성한다.

     이 경우 User Snapshot이 없으므로 OIDC claim에서 얻은 값을 사용한다.
     프론트엔드는 이 응답을 기준으로 사용 신청 화면으로 보낼 수 있다.
     */
    public static CurrentUserResponse notServiceUser(
            String keycloakSub,
            String username,
            String employeeNumber,
            String displayName,
            String email,
            String position
    ) {
        return new CurrentUserResponse(
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
     Keycloak 로그인도 되었고 User Service에도 존재하지만,
     ERP 서비스 이용 상태가 INACTIVE인 사용자 상태를 생성한다.

     이 경우 ERP 사용자 정보는 User Snapshot 기준 값을 사용한다.
     */
    public static CurrentUserResponse inactive(String username, User user) {
        return new CurrentUserResponse(
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
     Keycloak 로그인도 되었고 User Service에도 존재하지만,
     ERP 서비스 이용 승인을 기다리는 사용자 상태를 생성한다.

     UserStatus가 PENDING인 경우에 사용한다.
     */
    public static CurrentUserResponse pending(String username, User user) {
        return new CurrentUserResponse(
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
     Keycloak 로그인도 되었고,
     User Service에도 ERP 사용자로 등록되어 있으며,
     현재 ERP 서비스 이용 상태가 ACTIVE인 사용자 상태를 생성한다.

     일반적으로 프론트엔드는 이 응답을 받으면 메인 화면 또는 대시보드로 진입시킬 수 있다.
     */
    public static CurrentUserResponse active(String username, User user) {
        return new CurrentUserResponse(
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