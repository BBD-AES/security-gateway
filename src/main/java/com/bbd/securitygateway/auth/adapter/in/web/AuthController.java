package com.bbd.securitygateway.auth.adapter.in.web;

import com.bbd.securitygateway.auth.adapter.in.security.AuthPrincipalExtractor;
import com.bbd.securitygateway.auth.adapter.in.web.response.CurrentUserResponse;
import com.bbd.securitygateway.auth.application.model.AuthPrincipal;
import com.bbd.securitygateway.auth.application.model.CurrentUserResult;
import com.bbd.securitygateway.auth.application.port.in.GetCurrentUserUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/*
 현재 브라우저 사용자의 Gateway 세션 로그인 상태와
 Keycloak/OIDC 기본 사용자 정보를 반환하는 Web Adapter.

 이 컨트롤러는 adapter.in.web 계층에 속한다.

 역할:
 - Spring Security가 넘겨준 Authentication을 받는다.
 - Authentication을 AuthPrincipal로 변환한다.
 - application use case를 호출한다.
 - application 결과 모델인 CurrentUserResult를 CurrentUserResponse로 변환해 반환한다.

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
     현재 브라우저 사용자의 로그인 상태를 조회한다.

     프론트는 이 API를 호출해서
     1) 현재 Gateway 세션 기준 로그인되어 있는지
     2) 로그인되어 있다면 Keycloak/OIDC 기본 사용자 정보가 무엇인지
     확인할 수 있다.

     이 API는 ERP 사용자 등록 여부나 권한을 판단하지 않는다.

     처리 흐름:
     1. Spring Security가 Authentication을 메서드 파라미터로 넘겨준다.
     2. AuthPrincipalExtractor가 Authentication을 AuthPrincipal로 변환한다.
     3. GetCurrentUserUseCase가 Gateway 기준 현재 사용자 상태를 판단한다.
     4. CurrentUserResult를 CurrentUserResponse로 변환해 응답한다.
     */
    @GetMapping("/api/auth/me")
    public CurrentUserResponse me(Authentication authentication) {
        AuthPrincipal principal = authPrincipalExtractor.extract(authentication);

        CurrentUserResult result = getCurrentUserUseCase.getCurrentUser(principal);

        return CurrentUserResponse.from(result);
    }

    @GetMapping("/api/auth/token")
    public ResponseEntity<String> token(
            @RegisteredOAuth2AuthorizedClient("keycloak")
            OAuth2AuthorizedClient authorizedClient
    ) {
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            return ResponseEntity.status(401).body("로그인이 필요합니다.");
        }

        return ResponseEntity.ok(authorizedClient.getAccessToken().getTokenValue());
    }
}