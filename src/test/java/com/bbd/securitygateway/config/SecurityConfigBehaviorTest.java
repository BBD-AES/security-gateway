package com.bbd.securitygateway.config;

import com.bbd.securitygateway.auth.adapter.in.security.MobileSessionStore;
import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "security-gateway.frontend.base-url=http://frontend.test:3000",
        "security-gateway.frontend.allowed-origins=http://frontend.test:3000",
        "USER_SERVICE_URI=http://localhost:18081",
        "ITEM_SERVICE_URI=http://localhost:18082",
        "INVENTORY_SERVICE_URI=http://localhost:18083",
        "PROCUREMENT_SERVICE_URI=http://localhost:18084",
        "SALES_SERVICE_URI=http://localhost:18085",
        "COOKIE_SECURE=false",
        "security-gateway.mobile-session.enabled=true"
})
@Import(TestSessionRepositoryConfig.class)
class SecurityConfigBehaviorTest {

    private static final String FRONTEND_ORIGIN = "http://frontend.test:3000";

    @Autowired
    private WebApplicationContext context;

    @Autowired
    @Qualifier("springSecurityFilterChain")
    private Filter springSecurityFilterChain;

    @Autowired
    private SessionRegistry sessionRegistry;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .addFilters(springSecurityFilterChain)
                .build();
    }

    @Test
    void bearer_토큰이_있으면_bearer_전용_필터체인에서_401로_응답한다() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("Bearer")));
    }

    @Test
    void 유효한_bearer_토큰이면_api_auth_me를_모바일_인증_상태로_응답한다() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid-mobile-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authenticated").value(true))
                .andExpect(jsonPath("$.keycloakSub").value("mobile-keycloak-sub-1"))
                .andExpect(jsonPath("$.username").value("MOBILE001"))
                .andExpect(jsonPath("$.employeeNumber").value("MOBILE001"))
                .andExpect(jsonPath("$.displayName").value("모바일사용자"))
                .andExpect(jsonPath("$.email").value("mobile@example.com"))
                .andExpect(jsonPath("$.position").value("driver"))
                .andExpect(jsonPath("$.message").value("로그인된 사용자입니다."));
    }

    @Test
    void 새_모바일_세션이_등록되면_기존_모바일_세션은_401로_응답한다() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-session-old"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-session-new"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-session-old"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("AUTH003"));
    }

    @Test
    void 모바일_로그아웃은_현재_모바일_세션_슬롯을_정리한다() throws Exception {
        mockMvc.perform(get("/api/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-session-logout"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/mobile/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-session-logout"))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/auth/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer mobile-session-logout"))
                .andExpect(status().isOk());
    }

    @Test
    void bearer_토큰이_없고_세션도_없으면_api_auth_me는_로그인을_요구한다() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void 허용된_origin의_cors_preflight를_처리한다() throws Exception {
        mockMvc.perform(options("/api/auth/me")
                        .header(HttpHeaders.ORIGIN, FRONTEND_ORIGIN)
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "Authorization"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, FRONTEND_ORIGIN))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, containsString("GET")))
                .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, containsString("Authorization")));
    }

    @Test
    void 인증이_필요한_post_요청은_csrf보다_먼저_로그인을_요구한다() throws Exception {
        mockMvc.perform(post("/api/auth/me"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void gateway_health는_로그인_없이_허용한다() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(content().string("ok"));
    }

    @Test
    void user_scim_경로는_gateway_public_endpoint가_아니므로_인증을_요구한다() throws Exception {
        mockMvc.perform(get("/user/scim/v2/Users"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void 세션_레지스트리는_spring_session_기반_구현을_사용한다() {
        assertInstanceOf(SpringSessionBackedSessionRegistry.class, sessionRegistry);
    }

    @TestConfiguration
    static class SecurityTestConfig {

        @Bean
        @Primary
        JwtDecoder jwtDecoder() {
            return token -> {
                if ("invalid-token".equals(token)) {
                    throw new BadJwtException("테스트용 유효하지 않은 토큰입니다.");
                }

                if ("mobile-session-old".equals(token)) {
                    return mobileJwt(token, "same-mobile-user", "old-session", Instant.parse("2026-06-25T00:00:00Z"));
                }

                if ("mobile-session-new".equals(token)) {
                    return mobileJwt(token, "same-mobile-user", "new-session", Instant.parse("2026-06-25T00:01:00Z"));
                }

                if ("mobile-session-logout".equals(token)) {
                    return mobileJwt(token, "logout-mobile-user", "logout-session", Instant.parse("2026-06-25T00:00:00Z"));
                }

                return Jwt.withTokenValue(token)
                        .header("alg", "none")
                        .subject("mobile-keycloak-sub-1")
                        .claim("azp", "bbd-mobile-android")
                        .claim("sid", "valid-mobile-session")
                        .claim("auth_time", Instant.parse("2026-06-25T00:00:00Z").getEpochSecond())
                        .claim("preferred_username", "MOBILE001")
                        .claim("employee_number", "MOBILE001")
                        .claim("name", "모바일사용자")
                        .claim("email", "mobile@example.com")
                        .claim("position", "driver")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(60))
                        .build();
            };
        }

        private Jwt mobileJwt(String tokenValue, String subject, String sessionId, Instant authenticatedAt) {
            return Jwt.withTokenValue(tokenValue)
                    .header("alg", "none")
                    .subject(subject)
                    .claim("azp", "bbd-mobile-android")
                    .claim("sid", sessionId)
                    .claim("auth_time", authenticatedAt.getEpochSecond())
                    .claim("preferred_username", "MOBILE001")
                    .claim("employee_number", "MOBILE001")
                    .claim("name", "모바일사용자")
                    .claim("email", "mobile@example.com")
                    .claim("position", "driver")
                    .issuedAt(authenticatedAt)
                    .expiresAt(authenticatedAt.plusSeconds(300))
                    .build();
        }

        @Bean
        @Primary
        MobileSessionStore mobileSessionStore() {
            return new InMemoryMobileSessionStore();
        }

        @Bean
        @Primary
        ClientRegistrationRepository clientRegistrationRepository() {
            ClientRegistration keycloak = ClientRegistration.withRegistrationId("keycloak")
                    .clientId("test-client")
                    .clientSecret("test-secret")
                    .clientName("keycloak")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .scope("openid", "profile", "email")
                    .authorizationUri("http://localhost/oauth2/authorize")
                    .tokenUri("http://localhost/oauth2/token")
                    .jwkSetUri("http://localhost/oauth2/jwks")
                    .userInfoUri("http://localhost/userinfo")
                    .userNameAttributeName("sub")
                    .build();

            return new InMemoryClientRegistrationRepository(keycloak);
        }

        private static class InMemoryMobileSessionStore implements MobileSessionStore {

            private final Map<String, MobileSessionRecord> sessions = new ConcurrentHashMap<>();

            @Override
            public boolean registerOrValidate(String userSub, String sessionId, Instant authenticatedAt, Duration ttl) {
                MobileSessionRecord incoming = new MobileSessionRecord(sessionId, authenticatedAt);
                MobileSessionRecord current = sessions.get(userSub);

                if (current == null || current.sessionId().equals(sessionId)
                        || !incoming.authenticatedAt().isBefore(current.authenticatedAt())) {
                    sessions.put(userSub, incoming);
                    return true;
                }

                return false;
            }

            @Override
            public void removeIfCurrent(String userSub, String sessionId) {
                sessions.computeIfPresent(
                        userSub,
                        (ignored, current) -> current.sessionId().equals(sessionId) ? null : current
                );
            }
        }

        private record MobileSessionRecord(String sessionId, Instant authenticatedAt) {
        }
    }
}
