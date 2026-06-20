package com.bbd.securitygateway.auth.adapter.in.security;

import com.bbd.securitygateway.auth.application.model.AuthPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthPrincipalExtractorTest {

    private final AuthPrincipalExtractor extractor =
            new AuthPrincipalExtractor(new OidcUserSubjectExtractor());

    @Test
    void authentication이_null이면_인증되지_않은_사용자로_변환한다() {
        AuthPrincipal principal = extractor.extract(null);

        assertUnauthenticated(principal);
    }

    @Test
    void 인증되지_않은_authentication이면_인증되지_않은_사용자로_변환한다() {
        Authentication authentication =
                new UsernamePasswordAuthenticationToken("user", "password");

        AuthPrincipal principal = extractor.extract(authentication);

        assertUnauthenticated(principal);
    }

    @Test
    void anonymous_authentication이면_인증되지_않은_사용자로_변환한다() {
        Authentication authentication = new AnonymousAuthenticationToken(
                "anonymous-key",
                "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")
        );

        AuthPrincipal principal = extractor.extract(authentication);

        assertUnauthenticated(principal);
    }

    @Test
    void oidc_user이면_keycloak_claim을_auth_principal로_변환한다() {
        AuthPrincipal principal = extractor.extract(authentication(oidcUser(Map.of(
                "sub", "keycloak-sub-1",
                "preferred_username", "HQ001",
                "employee_number", "HQ001",
                "name", "홍길동",
                "email", "hong@example.com",
                "position", "manager"
        ))));

        assertTrue(principal.authenticated());
        assertEquals("keycloak-sub-1", principal.keycloakSub());
        assertEquals("HQ001", principal.username());
        assertEquals("HQ001", principal.employeeNumber());
        assertEquals("홍길동", principal.displayName());
        assertEquals("hong@example.com", principal.email());
        assertEquals("manager", principal.position());
    }

    @Test
    void 예상하지_않은_principal_타입이면_인증되지_않은_사용자로_처리한다() {
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                "plain-user",
                "n/a",
                AuthorityUtils.createAuthorityList("ROLE_USER")
        );

        AuthPrincipal principal = extractor.extract(authentication);

        assertUnauthenticated(principal);
    }

    private Authentication authentication(OidcUser oidcUser) {
        return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(), "keycloak");
    }

    private OidcUser oidcUser(Map<String, Object> claims) {
        OidcIdToken idToken = new OidcIdToken(
                "id-token",
                Instant.now(),
                Instant.now().plusSeconds(60),
                claims
        );

        return new DefaultOidcUser(List.of(), idToken);
    }

    private void assertUnauthenticated(AuthPrincipal principal) {
        assertFalse(principal.authenticated());
        assertNull(principal.keycloakSub());
        assertNull(principal.username());
        assertNull(principal.employeeNumber());
        assertNull(principal.displayName());
        assertNull(principal.email());
        assertNull(principal.position());
    }
}
