package com.bbd.securitygateway.auth.adapter.in.web;

import com.bbd.securitygateway.auth.adapter.in.security.AuthPrincipalExtractor;
import com.bbd.securitygateway.auth.application.model.AuthPrincipal;
import com.bbd.securitygateway.auth.application.model.CurrentUserResult;
import com.bbd.securitygateway.auth.application.port.in.GetCurrentUserUseCase;
import com.bbd.securitygateway.global.error.ApiException;
import com.bbd.securitygateway.global.error.dto.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/*
 현재 브라우저 사용자의 Gateway 세션 로그인 상태와
 Keycloak/OIDC 기본 사용자 정보를 반환하는 Web Adapter.


 이 컨트롤러는 adapter.in.web 계층에 속한다.

 역할:
 - Spring Security가 넘겨준 Authentication을 받는다.
 - Authentication을 AuthPrincipal로 변환한다.
 - application use case를 호출한다.
 - application 결과 모델인 CurrentUserResult를 그대로 반환한다.

 이 컨트롤러는 User Service를 직접 호출하지 않는다.
 Redis의 UserSnapshot도 조회하지 않는다.
 role, tenancy, status, permission 같은 ERP 인가 판단도 하지 않는다.

 해당 ERP 인가 판단은 각 MSA가 Access Token을 직접 검증한 뒤,
 JWT sub를 기준으로 Redis UserSnapshot을 조회해서 수행한다.

 Gateway는 /api/auth/me에서는 현재 웹 세션 로그인 상태만 확인하고,
 하위 MSA 호출 시에는 Access Token Relay를 통해
 Authorization: Bearer <access-token>을 전달한다.
 */
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthPrincipalExtractor authPrincipalExtractor;
    private final GetCurrentUserUseCase getCurrentUserUseCase;

    /*
     1) 현재 Gateway 세션 기준 로그인되어 있는지
     2) 로그인되어 있다면 Keycloak/OIDC 기본 사용자 정보가 무엇인지
     확인할 수 있다.

     담기는 값:
     - authenticated: Gateway 세션 / Spring Security 기준 인증 여부
     - keycloakSub: Keycloak 사용자의 고유 식별자(OIDC sub claim)
     - username: Keycloak/OIDC 로그인 식별자(preferred_username 등)
     - employeeNumber: Keycloak claim에서 얻은 사번
     - displayName: Keycloak claim에서 얻은 사용자 표시 이름
     - email: Keycloak claim에서 얻은 이메일
     - position: Keycloak claim에서 얻은 직책
     - message: 현재 로그인 상태를 설명하는 메시지
     */
    @GetMapping("/api/auth/me")
    // CurrentUserResult = 삭제된 CurrentUserResponse
    // Authentication은 Spring에서 주는 객체
    public CurrentUserResult me(Authentication authentication) {
        // principal은 로그인 여부 / 로그인 성공 시 정보가 들어있다.
        AuthPrincipal principal = authPrincipalExtractor.extract(authentication);

        // principal을 가지고 getCurrentUser로 처리 - principal에 로그인 성공 여부에 대한 message까지 첨부해서 리턴한다.
        return getCurrentUserUseCase.getCurrentUser(principal);
    }

    
    @GetMapping("/api/auth/token")
    public ResponseEntity<String> token(
            @RegisteredOAuth2AuthorizedClient("keycloak")
            OAuth2AuthorizedClient authorizedClient
    ) {
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            throw new ApiException(ErrorCode.AUTH_UNAUTHENTICATED);
        }

        return ResponseEntity.ok(authorizedClient.getAccessToken().getTokenValue());
    }
}
