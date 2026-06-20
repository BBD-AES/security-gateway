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

 해당 ERP 인가 판단은 각 MSA가 Access Token을 직접 검증한 뒤,
 JWT sub를 기준으로 Redis UserSnapshot을 조회해서 수행한다.

 Gateway는 하위 MSA 호출 시 Access Token Relay를 통해
 Authorization: Bearer <access-token>을 전달한다.

 application 계층은 웹 응답 DTO를 직접 반환하지 않는다.
 이 유스케이스는 CurrentUserResult라는 application 결과 모델을 반환한다.

 다만 /api/auth/me는 현재 CurrentUserResult와 외부 JSON 응답 스키마가
 완전히 같은 단순 조회 슬라이스이다.
 그래서 adapter.in.web 계층에서 별도 Response DTO로 한 번 더 복사하지 않고,
 CurrentUserResult를 그대로 응답으로 사용한다.
 응답 스키마가 application 결과 모델과 달라지는 시점에는
 adapter.in.web 전용 Response DTO를 다시 분리한다.
 */
public interface GetCurrentUserUseCase {

    CurrentUserResult getCurrentUser(AuthPrincipal principal);
}
