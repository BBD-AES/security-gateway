package com.bbd.securitygateway.auth.application.port.out;

import com.bbd.securitygateway.auth.domain.User;

import java.util.Optional;

// application service가 외부 시스템을 사용하기 위해 나가는 출구

/*
 User Service에서 ERP 사용자 정보를 조회하기 위한 Outbound Port.

 Gateway는 User Service DB를 직접 조회하지 않는다.
 실제 HTTP 호출은 adapter.out.user.UserServiceClient에서 구현한다.
 */
public interface LoadUserPort {
    // Keycloak sub 기준으로 User Service의 ERP 사용자 정보를 조회한다.
    Optional<User> loadByKeycloakSub(String keycloakSub);
}