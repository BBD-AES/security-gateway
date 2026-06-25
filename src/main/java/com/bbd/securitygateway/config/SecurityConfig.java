package com.bbd.securitygateway.config;

import com.bbd.securitygateway.auth.adapter.in.security.ApiAwareSessionExpiredStrategy;
import com.bbd.securitygateway.auth.adapter.in.security.ApiExceptionAccessDeniedHandler;
import com.bbd.securitygateway.auth.adapter.in.security.ApiExceptionAuthenticationEntryPoint;
import com.bbd.securitygateway.auth.adapter.in.security.MobileSessionLimitFilter;
import com.bbd.securitygateway.auth.adapter.in.security.OidcLoginSuccessHandler;
import com.bbd.securitygateway.auth.adapter.in.security.OidcUserSubjectExtractor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

// SecurityConfig 파일: 이 서버로 들어오는 HTTP 요청을 Spring Security가 어떻게 처리할지 정하는 파일

// Spring Bean 설정 클래스
@Configuration
public class SecurityConfig {

    private static final String[] PUBLIC_ENDPOINTS = {
            "/error",
            "/health",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/v3/api-docs/**",
            "/v3/api-docs.yaml",
            "/user/health",
            "/user/actuator/health",
            "/user/swagger-ui/**",
            "/user/swagger-ui.html",
            "/user/v3/api-docs/**",
            "/item/health",
            "/item/actuator/health",
            "/item/swagger-ui/**",
            "/item/swagger-ui.html",
            "/item/v3/api-docs/**",
            "/inventory/health",
            "/inventory/actuator/health",
            "/inventory/swagger-ui/**",
            "/inventory/swagger-ui.html",
            "/inventory/v3/api-docs/**",
            "/procurement/health",
            "/procurement/actuator/health",
            "/procurement/swagger-ui/**",
            "/procurement/swagger-ui.html",
            "/procurement/v3/api-docs/**",
            "/sales/health",
            "/sales/actuator/health",
            "/sales/swagger-ui/**",
            "/sales/swagger-ui.html",
            "/sales/v3/api-docs/**"
    };

    private final FrontendProperties frontendProperties;

    public SecurityConfig(FrontendProperties frontendProperties) {
        this.frontendProperties = frontendProperties;
    }

    /*
    1. Authorization: Bearer 토큰이 있는 요청
    모바일/앱 또는 토큰 기반 API 요청으로 보고 JWT Resource Server 방식으로 처리한다.

    2. Bearer 토큰이 없는 일반 브라우저 요청
    웹 요청으로 보고 OAuth2/OIDC 로그인 + Redis 기반 HttpSession 방식으로 처리한다.

    3. 로그아웃 처리
    - 웹: Redis에 저장된 Gateway 세션 종료 + Keycloak OIDC 로그아웃
    - 앱/토큰 요청: 서버 세션이 없으므로 기본적으로 클라이언트 토큰 삭제 또는 별도 revoke 정책 사용

    4. CSRF/CORS를 어떻게 처리할지 정한다.
    - 웹: JSESSIONID 쿠키 기반이므로 운영 전에는 CSRF 방어를 다시 적용해야 한다.
    - 앱/토큰 요청: Authorization 헤더 기반 stateless 인증이므로 CSRF 비활성화
    */

    // 모바일 전용 + swagger
    @Bean
    @Order(1)
    public SecurityFilterChain bearerTokenSecurityFilterChain(
            HttpSecurity http,
            CorsConfigurationSource corsConfigurationSource,
            ApiExceptionAuthenticationEntryPoint authenticationEntryPoint,
            ApiExceptionAccessDeniedHandler accessDeniedHandler,
            MobileSessionLimitFilter mobileSessionLimitFilter
    ) throws Exception {
        return http
                // 모바일 전용 - Bearer 토큰
                // Authorization: Bearer 헤더가 붙어 있는 경우에만 이 SecurityFilterChain을 적용
                .securityMatcher(request -> {
                    String authorization = request.getHeader("Authorization");
                    return authorization != null
                            && authorization.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length());
                })
                // 로그인 유무에 따른 허용
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                )
                // cors
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                // csrf 비활성화
                .csrf(AbstractHttpConfigurer::disable)
                // 세션 저장 x
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // Bearer 토큰 요청의 인증/인가 실패는 컨트롤러 전에 발생하므로
                // HandlerExceptionResolver에 ApiException을 넘겨 공통 GlobalExceptionHandler로 처리한다.
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        // 인증 시 오류
                        .authenticationEntryPoint(authenticationEntryPoint)
                        // 인가 시 오류 -> 거의 없음
                        .accessDeniedHandler(accessDeniedHandler)
                )

                // Authorization: Bearer 형식으로 전달된 Keycloak Access Token을 검증한다.
                // JwtAuthenticationToken 생성
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                )
                .addFilterAfter(mobileSessionLimitFilter, BearerTokenAuthenticationFilter.class)
                .build();
    }

    // 웹 전용
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http,
                                                      LogoutSuccessHandler oidcLogoutSuccessHandler,
                                                      OidcLoginSuccessHandler oidcLoginSuccessHandler,
                                                      CorsConfigurationSource corsConfigurationSource,
                                                      SessionRegistry sessionRegistry,
                                                      ApiAwareSessionExpiredStrategy sessionExpiredStrategy,
                                                      OAuth2AuthorizationRequestResolver authorizationRequestResolver
    ) throws Exception {

        return http
                .authorizeHttpRequests(auth -> auth
                        // 아래는 로그인 없이 허용
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        // 나머지는 전부 로그인을 거쳐야함
                        // /api/csrf는 로그인 후 호출한다.
                        // anyRequest().authenticated()에 의해 인증된 사용자만 CSRF 토큰을 받을 수 있다.
                        .anyRequest().authenticated()
                )
                // Keycloak을 이용하는데,
                // Spring 서버가 OAuth2/OIDC Client가 돼서,
                // 사용자를 Keycloak 로그인 페이지로 리다이렉트하고,
                // 로그인 성공 후 callback을 받아 세션을 만드는 기능
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(authorizationRequestResolver)
                        )
                        .successHandler(oidcLoginSuccessHandler)
                )
                // 로그아웃은 어떻게 할지 정한다.
                // 웹 브라우저 로그아웃은 Gateway의 /logout으로 처리한다.
                // Gateway 세션을 무효화하고, JSESSIONID 쿠키를 삭제한다.

                // 현재 컨트롤러를 사용하지 않는 상황
                // 하지만, Redis에 저장한 Refresh Token 삭제와 같이
                // 컨트롤러가 필요한 케이스들이 존재한다.

                // 하지만 이것도 logoutSuccessHandler로 처리 가능하다.
                .logout(logout -> logout
                        // 로그아웃 요청을 처리할 URI path를 지정한다.
                        // 기본값도 /logout이지만, 웹 브라우저 로그아웃 진입점을 명확히 하기 위해 명시한다.
                        .logoutUrl("/logout")
                        // Gateway의 HttpSession을 무효화하여 서버 측 세션 정보를 제거한다.
                        .invalidateHttpSession(true)
                        // 현재 SecurityContext의 Authentication 정보를 제거한다.
                        .clearAuthentication(true)
                        // 브라우저의 Gateway 세션 쿠키(JSESSIONID)를 삭제한다.
                        .deleteCookies("JSESSIONID")
                        // Gateway 로그아웃 성공 후 프론트 로그인 페이지로 이동한다.
                        .logoutSuccessHandler(oidcLogoutSuccessHandler)
                )


                // 6. CSRF/CORS는 어떻게 할지 정한다.
                // 1) CORS
                // 웹 브라우저는 Gateway와 origin이 다르면 CORS 설정이 필요하다.
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                // 2) CSRF
                // Gateway는 웹 브라우저와 세션 쿠키를 사용하므로 CSRF 보호가 필요하다.
                .csrf(AbstractHttpConfigurer::disable)

                // 7. 세션을 쓸지, JWT만 쓸지 정한다.
                // 현재 oauth2Login을 사용하면서
                // 웹 브라우저는 Redis 기반 Gateway 세션 + 세션 쿠키를 사용한다.
                // SessionCreationPolicy.IF_REQUIRED는 기본값에 가깝지만,
                // oauth2Login 기반 웹 세션 사용 의도를 명확히 하기 위해 명시한다. (SessionCreationPolicy.IF_REQUIRED)
                // 로그인 성공 시 세션 ID를 변경하여 세션 고정 공격을 방어한다.
                // changeSessionId()도 기본 전략에 가깝지만 보안 의도를 명시한다. (sessionFixation.changeSessionId())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::changeSessionId)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                        // 만료 세션: API/XHR → 401(프론트가 로그인으로 리다이렉트), 내비게이션 → 만료 페이지.
                        // (.expiredUrl 은 모든 요청을 302 시켜 SPA 가 만료를 감지 못 하던 문제 해소)
                        .expiredSessionStrategy(sessionExpiredStrategy)
                        .sessionRegistry(sessionRegistry)
                )
                .build();
    }


    // cors 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        // CORS 정책 객체를 생성
        CorsConfiguration config = new CorsConfiguration();

        // 요청을 허용할 프론트엔드 Origin 지정
        // Cross-Origin 요청에서는 쿠키를 기본적으로 안 보내지만
        // JSESSIONID 쿠키를 포함한 요청을 허용해야 하므로 allowCredentials(true)를 사용한다.
        // 이 경우 "*" 전체 허용은 사용할 수 없고, 정확한 Origin을 지정해야 한다.
        config.setAllowedOrigins(frontendProperties.allowedOrigins());


        // 허용할 HTTP 메서드 지정
        // OPTIONS는 브라우저가 실제 요청 전에 보내는 Preflight 요청 처리를 위해 필요
        config.setAllowedMethods(List.of(
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS"
        ));

        // 프론트엔드 요청에서 허용할 요청 헤더 지정
        // Authorization : Bearer Token 전달 시 사용
        // Content-Type : application/json 요청 시 사용
        // X-Requested-With : Ajax 요청 식별용으로 사용될 수 있음
        // X-XSRF-TOKEN : CSRF 토큰을 헤더로 전달할 때 사용
        // Idempotency-Key : 멱등 표준(POST/PATCH 재요청 dedup) 헤더 — 미허용 시 브라우저 preflight 가 막혀
        //                   웹 콘솔의 수주 생성/종료(@Idempotent) 가 CORS 로 차단됨. allowCredentials(true) 라 "*" 불가→명시.
        config.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "X-XSRF-TOKEN",
                "Idempotency-Key"
        ));

        // 쿠키, Authorization 헤더 등 인증 정보가 포함된 요청 허용
        // JSESSIONID 기반 세션 인증을 사용하려면 true 필요
        config.setAllowCredentials(true);


        // URL 패턴별 CORS 정책을 등록할 수 있는 Source 객체 생성
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // 모든 요청 경로에 위 CORS 정책 적용
        source.registerCorsConfiguration("/**", config);

        // Spring Security의 CORS 처리에서 사용할 설정 객체 반환
        return source;
    }


    /*
       현재 로그인된 사용자들의 세션 정보를 추적하기 위한 저장소 Bean.
       maximumSessions(1) 설정과 함께 사용되며,
       Keycloak sub 기준으로 어떤 principal이 어떤 세션을 가지고 있는지를 Redis 세션 인덱스로 관리한다.

       Spring Security의 maximumSessions(1)이
       기존 로그인 세션을 찾아 만료시키는 데 사용한다.
     */
    @Bean
    public <S extends Session> SessionRegistry sessionRegistry(
            FindByIndexNameSessionRepository<S> sessionRepository,
            OidcUserSubjectExtractor subjectExtractor
    ) {
        return new SpringSessionBackedSessionRegistry<>(sessionRepository) {
            @Override
            protected String name(Object principal) {
                return subjectExtractor.extract(principal).orElseGet(() -> super.name(principal));
            }
        };
    }


}
