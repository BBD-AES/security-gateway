package com.bbd.securitygateway.auth.application.service;

import com.bbd.securitygateway.auth.application.model.AuthPrincipal;
import com.bbd.securitygateway.auth.application.model.CurrentUserResult;
import com.bbd.securitygateway.auth.application.port.in.GetCurrentUserUseCase;
import org.springframework.stereotype.Service;

/*
 현재 요청 사용자의 Gateway 인증 상태를 조회하는 유스케이스 구현체.

 이 서비스는 /api/auth/me 요청에서 사용된다.

 이 클래스는 Spring Security의 Authentication, OidcUser, Jwt 같은 프레임워크 타입을 직접 다루지 않는다.
 대신 adapter 계층에서 Authentication/OidcUser/Jwt를 AuthPrincipal로 변환한 뒤 전달받는다.

 즉, application 계층은 Spring Security를 직접 알지 않고,
 현재 인증 사용자 정보를 표현하는 AuthPrincipal만 사용한다.

 처리 흐름:
 1. 인증되지 않은 사용자이면 unauthenticated 결과 반환
 2. 인증된 사용자이면 AuthPrincipal에 담긴 Keycloak/OIDC 기본 정보를 CurrentUserResult로 변환

 Gateway는 하위 MSA 호출 시 Access Token Relay를 통해
 Authorization: Bearer <access-token>을 전달한다.
 */
@Service
public class GetCurrentUserService implements GetCurrentUserUseCase {

    /*
     현재 요청 사용자의 Gateway 인증 상태를 조회한다.

     principal은 adapter 계층에서 Spring Security Authentication/OidcUser를 읽어
     application 계층이 사용할 수 있게 변환한 인증 사용자 정보이다.
     */
    @Override
    public CurrentUserResult getCurrentUser(AuthPrincipal principal) {
        if (!principal.authenticated()) {
            return CurrentUserResult.unauthenticated();
        }

        return CurrentUserResult.authenticated(principal);
    }
}
