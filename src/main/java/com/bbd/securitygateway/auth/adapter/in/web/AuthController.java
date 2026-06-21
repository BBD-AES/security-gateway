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

     처리 흐름:
     1. Spring Security가 Authentication을 메서드 파라미터로 넘겨준다.
     2. AuthPrincipalExtractor가 Authentication을 AuthPrincipal로 변환한다.
     3. GetCurrentUserUseCase가 Gateway 기준 현재 사용자 상태를 판단한다.
     4. CurrentUserResult를 그대로 JSON 응답으로 반환한다.
     */
    @GetMapping("/api/auth/me")
    public CurrentUserResult me(Authentication authentication) {
        AuthPrincipal principal = authPrincipalExtractor.extract(authentication);

        return getCurrentUserUseCase.getCurrentUser(principal);
    }

    // 최종 개발 시 삭제 예정 - 토큰 확인 가능
    @GetMapping("/api/auth/token")
    public ResponseEntity<String> token(
            // 현재 로그인한 사용자 세션에서 registration id가 keycloak인 OAuth2 클라이언트 정보를 꺼내서 authorizedClient에 넣어준다.
            @RegisteredOAuth2AuthorizedClient("keycloak")
            OAuth2AuthorizedClient authorizedClient
    ) {
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            throw new ApiException(ErrorCode.AUTH_UNAUTHENTICATED);
        }

        return ResponseEntity.ok(authorizedClient.getAccessToken().getTokenValue());
    }
}
