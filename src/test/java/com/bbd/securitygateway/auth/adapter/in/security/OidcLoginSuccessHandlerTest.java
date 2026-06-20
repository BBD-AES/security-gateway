package com.bbd.securitygateway.auth.adapter.in.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcLoginSuccessHandlerTest {

    private final OidcUserSubjectExtractor subjectExtractor = new OidcUserSubjectExtractor();

    @Test
    void 같은_사용자의_기존_세션을_만료시키고_현재_세션만_유지한다() throws Exception {
        SessionRegistryImpl sessionRegistry = new SessionRegistryImpl();
        OidcLoginSuccessHandler handler = new OidcLoginSuccessHandler(sessionRegistry, subjectExtractor);

        OidcUser previousPrincipal = oidcUser("same-user");
        OidcUser currentPrincipal = oidcUser("same-user");

        String previousSessionId = "previous-session-1234";
        MockHttpSession currentSession = new MockHttpSession(null, "current-session-5678");

        sessionRegistry.registerNewSession(previousSessionId, previousPrincipal);
        sessionRegistry.registerNewSession(currentSession.getId(), currentPrincipal);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/keycloak");
        request.setSession(currentSession);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication(currentPrincipal));

        assertTrue(sessionRegistry.getSessionInformation(previousSessionId).isExpired());
        assertFalse(sessionRegistry.getSessionInformation(currentSession.getId()).isExpired());
        assertEquals("http://localhost:5173/main", response.getRedirectedUrl());
    }

    @Test
    void 로그인_성공_흐름에서_세션이_없으면_로그인_에러_페이지로_보낸다() throws Exception {
        SessionRegistryImpl sessionRegistry = new SessionRegistryImpl();
        OidcLoginSuccessHandler handler = new OidcLoginSuccessHandler(sessionRegistry, subjectExtractor);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/keycloak");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication(oidcUser("same-user")));

        assertEquals("http://localhost:5173/login?error=session", response.getRedirectedUrl());
    }

    @Test
    void 예상하지_않은_principal_타입이면_세션_비교를_실패시킨다() {
        SessionRegistryImpl sessionRegistry = new SessionRegistryImpl();
        OidcLoginSuccessHandler handler = new OidcLoginSuccessHandler(sessionRegistry, subjectExtractor);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/keycloak");
        request.setSession(new MockHttpSession(null, "current-session-5678"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new UsernamePasswordAuthenticationToken("plain-user", "n/a");

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> handler.onAuthenticationSuccess(request, response, authentication)
        );

        assertTrue(exception.getMessage().contains("OIDC 로그인에서 예상하지 않은 principal 타입입니다"));
    }

    private Authentication authentication(OidcUser oidcUser) {
        return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(), "keycloak");
    }

    private OidcUser oidcUser(String subject) {
        OidcIdToken idToken = new OidcIdToken(
                "id-token",
                Instant.now(),
                Instant.now().plusSeconds(60),
                Map.of(
                        "sub", subject,
                        "preferred_username", subject,
                        "name", "테스트 사용자",
                        "email", subject + "@example.com"
                )
        );

        return new DefaultOidcUser(List.of(), idToken);
    }
}
