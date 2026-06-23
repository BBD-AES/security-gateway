package com.bbd.securitygateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/*
 OIDC 로그아웃 핸들러 Bean 설정.

 SecurityConfig가 필터체인 배선에 집중할 수 있도록
 Keycloak SSO 세션 종료용 핸들러 생성 책임을 별도 설정으로 분리한다.
 */
@Configuration
public class OidcLogoutConfig {

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler(
            // Spring Security가 등록한 OAuth2/OIDC Client 정보 저장소
            // 여기에는 yml에 설정한 Keycloak client-id, issuer-uri 등이 들어 있다.
            ClientRegistrationRepository clientRegistrationRepository,
            FrontendProperties frontendProperties
    ) {
        // OIDC RP-Initiated Logout을 처리하는 Spring Security 제공 핸들러.
        // 로그아웃 성공 시 현재 사용자의 ID Token과 ClientRegistration 정보를 이용해서
        // Keycloak 로그아웃 URL을 생성한다.
        OidcClientInitiatedLogoutSuccessHandler handler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);

        // Keycloak 로그아웃이 끝난 뒤 최종적으로 돌아올 프론트엔드 주소를 지정한다.
        // 이 값은 Keycloak 로그아웃 URL의 post_logout_redirect_uri 파라미터로 사용된다.
        handler.setPostLogoutRedirectUri(frontendProperties.loginUrl());

        return handler;
    }
}
