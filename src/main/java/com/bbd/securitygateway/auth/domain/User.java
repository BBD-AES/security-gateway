package com.bbd.securitygateway.auth.domain;

/*
 Gateway/Auth 도메인에서 사용하는 ERP 사용자 모델.

 이 User는 JPA Entity가 아니며, User Service의 users 테이블을 직접 표현하는 엔티티도 아니다.
 또한 User Service를 직접 호출하는 객체도 아니다.

 이 객체는 Gateway가 인증 흐름과 공통 사용자 상태 검증,
 그리고 하위 MSA로 전달할 사용자 컨텍스트 구성을 위해 들고 있는
 현재 시점의 ERP 사용자 정보를 표현하는 불변 데이터 모델이다.

 보통 다음과 같은 경우에 생성된다.

 - Keycloak 로그인 성공 후, keycloakSub 기준으로 User Service에서 내부 사용자 정보를 조회한 경우
 - 세션 또는 Redis 캐시에 저장된 사용자 정보를 다시 꺼낸 경우
 - User Service 응답 DTO를 Gateway 내부 도메인 모델로 변환한 경우

 역할 구분은 다음과 같다.

 - Keycloak
   사용자가 실제로 로그인 가능한 계정인지 인증한다.
   ID Token의 sub claim으로 Keycloak 사용자 식별자를 제공한다.

 - User Service
   ERP 서비스 기준의 사용자 정보, 권한, 소속, 상태를 관리한다.
   role, tenancyType, tenancyName, status, version의 기준 데이터가 된다.

 - Gateway의 User 모델
   Keycloak에서 인증된 사용자가 ERP 서비스에서 어떤 사용자로 해석되는지 담는다.
   이 객체 자체가 DB 조회나 HTTP 호출을 수행하지는 않는다.

 예를 들어:
 - Keycloak의 sub와 내부 User DB의 userId가 매핑된 결과를 담는다.
 - 현재 사용자가 ERP 서비스를 이용 가능한 상태인지 판단한다.
 - status/version 값을 기반으로 ERP 서비스 접근 가능 여부나 캐시 최신성을 판단한다.
 - role/tenancy 정보는 하위 MSA가 도메인별 인가를 수행할 수 있도록 사용자 컨텍스트로 전달된다.
 - 세션이나 Redis에 저장된 사용자 정보를 검증할 때 사용된다.
 */

// 값을 담기 위한 불변 데이터 클래스.
// record는 생성자, 필드 접근 메서드, equals/hashCode/toString을 자동으로 만들어준다.
public record User(

        /*
         User Service users 테이블의 내부 사용자 PK.

         Keycloak의 사용자 ID가 아니라,
         BBD ERP 서비스 내부에서 사용하는 사용자 식별자이다.
         */
        Long userId,

        /*
         Keycloak 사용자의 고유 식별자.

         OIDC ID Token의 sub claim에 해당한다.
         Keycloak 계정과 User Service의 내부 사용자를 연결하는 기준값이다.
         */
        String keycloakSub,

        /*
         사번.

         사용자가 업무적으로 식별되는 값이다.
         예: HQ001, BR001, ADMIN
         */
        String employeeNumber,

        /*
         사용자 이름.

         화면 표시, 감사 로그, 사용자 정보 응답 등에 사용할 수 있다.
         */
        String name,

        /*
         사용자 이메일.
         */
        String email,

        /*
         직책 또는 직무명.

         예:
         - 부장
         - 과장

         권한 판단 기준이 아니라,
         사용자 정보 표시나 업무 정보 표현에 사용하는 값이다.
         */
        String position,

        /*
         ERP 시스템 권한.

         예:
         - ADMIN
         - HQ_MANAGER
         - HQ_STAFF
         - BRANCH_MANAGER
         - BRANCH_STAFF

         API 접근 권한 판단에 사용할 수 있는 값이다.

         이 값은 Gateway가 직접 계산하지 않는다.
         Gateway는 User Service에서 조회했거나 세션/Redis에 캐시된 User Snapshot의 role 값을 사용한다.

         role의 기준 데이터는 User Service의 users.role이며,
         User Service는 회사 원천 데이터, IdP, HR 시스템 등에서 들어온 사용자/직무/소속 정보를 바탕으로
         이 값을 생성하거나 갱신할 수 있다.
        */
        String role,

        /*
         소속 유형.

         예:
         - HQ
         - BRANCH

         본사 사용자인지 지점 사용자인지 구분할 때 사용한다.
         */
        String tenancyType,

        /*
         소속 이름.

         예:
         - 본사
         - 강남 1지점

         지점별 데이터 접근 범위나 화면 표시에서 사용할 수 있다.
         */
        String tenancyName,

        /*
         ERP 서비스 내부 사용자 상태.

         이 값은 Keycloak 계정의 enabled/disabled 상태가 아니라,
         User Service 기준으로 해당 사용자가 ERP 서비스를 이용할 수 있는지를 나타낸다.

         예:
         - ACTIVE: ERP 서비스 이용 가능
         - INACTIVE: ERP 서비스 이용 중지
         - PENDING: ERP 서비스 이용 대기
         */
        UserStatus status,

        /*
         사용자 정보 버전.

         role, status, tenancy 정보처럼 권한 판단에 영향을 주는 값이 변경될 때 증가시킨다.

         세션이나 Redis 캐시에 저장된 사용자 정보가
         User Service의 최신 정보와 같은지 확인할 때 사용할 수 있다.
         */
        Long version
) {

    /*
     ERP 서비스 이용 가능 상태인지 확인한다.

     true이면 Gateway 기준으로 이 사용자는 ERP 서비스 요청을 계속 진행할 수 있다.
     */
    public boolean isActive() {
        return status == UserStatus.ACTIVE;
    }

    /*
     ERP 서비스 이용 중지 상태인지 확인한다.

     true이면 Keycloak 로그인 여부와 별개로,
     ERP 서비스 접근을 막아야 한다.
     */
    public boolean isInactive() {
        return status == UserStatus.INACTIVE;
    }

    /*
     ERP 서비스 이용 대기 상태인지 확인한다.

     true이면 내부 사용자 정보는 존재하지만,
     아직 ERP 서비스 이용 가능 상태로 확정되지 않은 사용자이다.
     */
    public boolean isPending() {
        return status == UserStatus.PENDING;
    }
}