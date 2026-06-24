package com.bbd.securitygateway.auth.adapter.in.security;

import com.bbd.securitygateway.config.FrontendProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.session.FindByIndexNameSessionRepository;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OidcLoginSuccessHandlerTest {

    private static final String FRONTEND_BASE_URL = "http://frontend.test:3000";

    private final OidcUserSubjectExtractor subjectExtractor = new OidcUserSubjectExtractor();
    private final FrontendProperties frontendProperties = frontendProperties();

    @Test
    void 로그인_성공_시_keycloak_sub를_세션_인덱스로_저장하고_main으로_보낸다() throws Exception {
        OidcLoginSuccessHandler handler = new OidcLoginSuccessHandler(
                subjectExtractor,
                frontendProperties
        );

        OidcUser currentPrincipal = oidcUser("same-user");

        MockHttpSession currentSession = new MockHttpSession(null, "current-session-5678");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/keycloak");
        request.setSession(currentSession);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication(currentPrincipal));

        assertEquals(
                "same-user",
                currentSession.getAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME)
        );
        assertEquals(FRONTEND_BASE_URL + "/main", response.getRedirectedUrl());
    }

    @Test
    void 로그인_성공_흐름에서_세션이_없으면_로그인_에러_페이지로_보낸다() throws Exception {
        OidcLoginSuccessHandler handler = new OidcLoginSuccessHandler(
                subjectExtractor,
                frontendProperties
        );

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login/oauth2/code/keycloak");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication(oidcUser("same-user")));

        assertEquals(FRONTEND_BASE_URL + "/login?error=session", response.getRedirectedUrl());
    }

    @Test
    void 예상하지_않은_principal_타입이면_세션_비교를_실패시킨다() {
        OidcLoginSuccessHandler handler = new OidcLoginSuccessHandler(
                subjectExtractor,
                frontendProperties
        );

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

    private FrontendProperties frontendProperties() {
        FrontendProperties properties = new FrontendProperties();
        properties.setBaseUrl(FRONTEND_BASE_URL);
        return properties;
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
