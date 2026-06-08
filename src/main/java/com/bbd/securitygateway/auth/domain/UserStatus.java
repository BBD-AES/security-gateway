package com.bbd.securitygateway.auth.domain;

/*
 User Service 기준의 ERP 사용자 정보.
 Gateway가 직접 DB를 조회하는 것이 아니라,
 User Service 조회 결과 또는 세션/Redis에 캐시된 User Snapshot을 사용한다.
 */
public enum UserStatus {

    /*
     ERP 서비스 이용 가능 상태.

     Keycloak 로그인 후 내부 User DB에 매핑되었고,
     실제 ERP 기능 접근이 허용된 사용자이다.
     */
    ACTIVE,

    /*
     ERP 서비스 이용 중지 상태.

     Keycloak 계정은 존재하고 로그인도 가능할 수 있지만,
     우리 ERP 서비스 내부 정책상 접근이 막힌 사용자이다.

     예:
     - 퇴사자
     - 관리자에 의해 ERP 접근이 중지된 사용자
     - 일시적으로 서비스 이용이 중지된 사용자
     */
    INACTIVE,

    /*
     ERP 서비스 이용 대기 상태.

     Keycloak 로그인은 가능하지만,
     User Service 기준으로 아직 ERP 서비스 이용 가능 상태로 확정되지 않은 사용자이다.

     예:
     - 회사 원천 시스템에서는 직원으로 확인되었지만 ERP 사용 승인 전
     - User Service에는 사용자 정보가 존재하지만 아직 ACTIVE 처리되지 않은 사용자
     */
    PENDING
}