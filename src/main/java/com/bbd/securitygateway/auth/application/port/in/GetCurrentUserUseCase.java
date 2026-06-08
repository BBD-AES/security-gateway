package com.bbd.securitygateway.auth.application.port.in;

import com.bbd.securitygateway.auth.adapter.in.web.response.CurrentUserResponse;
import com.bbd.securitygateway.auth.application.model.AuthPrincipal;

/*
 현재 요청 사용자의 상태를 조회하는 유스케이스.
 현재 사용자 조회 기능을 외부에서 호출하려면 이 인터페이스로 들어와라.

 이 유스케이스는 /api/auth/me에서 사용된다.

 역할:
 - 로그인 여부 확인
 - Keycloak 인증 사용자 정보 확인
 - User Snapshot 조회
 - User Service 등록 여부 확인
 - 프론트에 내려줄 CurrentUserResponse 생성
 */
public interface GetCurrentUserUseCase {

    CurrentUserResponse getCurrentUser(AuthPrincipal principal);
}