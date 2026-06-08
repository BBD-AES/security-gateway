package com.bbd.securitygateway.auth.application.port.out;

import com.bbd.securitygateway.auth.domain.User;

import java.util.Optional;

// application service가 외부 시스템을 사용하기 위해 나가는 출구

/*
 세션 또는 Redis에 저장된 User Snapshot을 조회하기 위한 Outbound Port.

 일반 요청에서는 User Service를 매번 호출하지 않고,
 먼저 캐시된 User Snapshot을 사용한다.
 */
public interface LoadUserSnapshotPort {
    Optional<User> loadSnapshot(String keycloakSub);
}