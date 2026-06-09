package com.bbd.securitygateway.auth.application.port.in;

import com.bbd.securitygateway.auth.application.model.AuthPrincipal;
import com.bbd.securitygateway.auth.application.model.CurrentUserResult;

/*
 현재 요청 사용자의 Gateway 세션 인증 상태를 조회하는 유스케이스.

 이 유스케이스는 adapter.in.web 계층의 /api/auth/me에서 호출할 수 있다.

 역할:
 - Gateway 세션 기준 로그인 여부 확인
 - Keycloak/OIDC 인증 사용자 기본 정보 확인
 - 현재 사용자 상태를 CurrentUserResult로 반환

 이 유스케이스는 ERP 사용자 등록 여부, role, tenancy, status, permission을 판단하지 않는다.

 해당 ERP 인가 판단은 각 MSA의 경량 인가 프레임워크가
 Redis의 UserSnapshot을 조회해서 수행한다.

 application 계층은 웹 응답 DTO를 직접 반환하지 않는다.
 따라서 CurrentUserResponse를 만들지 않고,
 CurrentUserResult라는 application 결과 모델을 반환한다.

 adapter.in.web 계층은 CurrentUserResult를 받아
 CurrentUserResponse로 변환한 뒤 클라이언트에 응답한다.
 */
public interface GetCurrentUserUseCase {

    CurrentUserResult getCurrentUser(AuthPrincipal principal);
}