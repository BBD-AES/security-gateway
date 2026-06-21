package com.bbd.securitygateway.auth.adapter.in.web;

import com.bbd.securitygateway.auth.adapter.in.security.AuthPrincipalExtractor;
import com.bbd.securitygateway.auth.adapter.in.security.OidcUserSubjectExtractor;
import com.bbd.securitygateway.auth.application.model.CurrentUserResult;
import com.bbd.securitygateway.auth.application.service.GetCurrentUserService;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthControllerTest {

    private final AuthController authController = new AuthController(
            new AuthPrincipalExtractor(new OidcUserSubjectExtractor()),
            new GetCurrentUserService()
    );

    @Test
    void me는_인증된_사용자_정보를_CurrentUserResult로_그대로_반환한다() {
        CurrentUserResult result = authController.me(authentication(oidcUser()));

        assertTrue(result.authenticated());
        assertEquals("keycloak-sub-1", result.keycloakSub());
        assertEquals("HQ001", result.username());
        assertEquals("HQ001", result.employeeNumber());
        assertEquals("홍길동", result.displayName());
        assertEquals("hong@example.com", result.email());
        assertEquals("manager", result.position());
        assertEquals("로그인된 사용자입니다.", result.message());
    }

    @Test
    void me는_모바일_bearer_jwt_사용자_정보도_CurrentUserResult로_반환한다() {
        CurrentUserResult result = authController.me(jwtAuthentication());

        assertTrue(result.authenticated());
        assertEquals("mobile-keycloak-sub-1", result.keycloakSub());
        assertEquals("MOBILE001", result.username());
        assertEquals("MOBILE001", result.employeeNumber());
        assertEquals("모바일사용자", result.displayName());
        assertEquals("mobile@example.com", result.email());
        assertEquals("driver", result.position());
        assertEquals("로그인된 사용자입니다.", result.message());
    }

    @Test
    void me는_인증되지_않은_요청을_로그인_필요_상태로_반환한다() {
        CurrentUserResult result = authController.me(null);

        assertFalse(result.authenticated());
        assertNull(result.keycloakSub());
        assertNull(result.username());
        assertNull(result.employeeNumber());
        assertNull(result.displayName());
        assertNull(result.email());
        assertNull(result.position());
        assertEquals("로그인이 필요합니다.", result.message());
    }

    private Authentication authentication(OidcUser oidcUser) {
        return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(), "keycloak");
    }

    private OidcUser oidcUser() {
        OidcIdToken idToken = new OidcIdToken(
                "id-token",
                Instant.now(),
                Instant.now().plusSeconds(60),
                Map.of(
                        "sub", "keycloak-sub-1",
                        "preferred_username", "HQ001",
                        "employee_number", "HQ001",
                        "name", "홍길동",
                        "email", "hong@example.com",
                        "position", "manager"
                )
        );

        return new DefaultOidcUser(List.of(), idToken);
    }

    private Authentication jwtAuthentication() {
        Jwt jwt = Jwt.withTokenValue("access-token")
                .header("alg", "none")
                .subject("mobile-keycloak-sub-1")
                .claim("preferred_username", "MOBILE001")
                .claim("employee_number", "MOBILE001")
                .claim("name", "모바일사용자")
                .claim("email", "mobile@example.com")
                .claim("position", "driver")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();

        return new JwtAuthenticationToken(jwt, AuthorityUtils.createAuthorityList("SCOPE_openid"));
    }
}
