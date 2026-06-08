package com.bbd.securitygateway.auth.application.port.out;

import com.bbd.securitygateway.auth.domain.User;


// application service가 외부 시스템을 사용하기 위해 나가는 출구

/*
 User Service에서 조회한 ERP 사용자 정보를
 세션 또는 Redis에 User Snapshot으로 저장하기 위한 Outbound Port.
 */
public interface SaveUserSnapshotPort {
    void saveSnapshot(User user);
}