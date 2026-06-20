package com.bbd.securitygateway.config;

import com.bbd.securitygateway.auth.adapter.in.security.ApiExceptionAccessDeniedHandler;
import com.bbd.securitygateway.auth.adapter.in.security.ApiExceptionAuthenticationEntryPoint;
import com.bbd.securitygateway.auth.adapter.in.security.OidcLoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

// SecurityConfig 파일: 이 서버로 들어오는 HTTP 요청을 Spring Security가 어떻게 처리할지 정하는 파일

// Spring Bean 설정 클래스
@Configuration
public class SecurityConfig {

    /*
    SecurityConfig 파일: 이 서버로 들어오는 HTTP 요청을 Spring Security가 어떻게 처리할지 정하는 파일
    이 설정에서는 요청 성격에 따라 SecurityFilterChain을 분리한다.
    1) Authorization: Bearer 토큰이 있는 요청
    → 모바일/앱 또는 토큰 기반 API 요청으로 보고 JWT Resource Server 방식으로 처리한다.
    2) Bearer 토큰이 없는 일반 브라우저 요청
    → 웹 요청으로 보고 OAuth2/OIDC 로그인 + JSESSIONID 세션 방식으로 처리한다.

    각 SecurityFilterChain에서 정하는 것
    1. 어떤 URL은 로그인 없이 허용할지 정한다.
    2. 어떤 URL은 인증이 필요할지 정한다.
    3. 어떤 URL은 특정 Role이 있어야 접근 가능한지 정한다.
    현재 Gateway에서는 Role 기반 인가는 최소화하고, 세부 인가는 각 MSA에서 처리한다.
    4. 인증 방식이 무엇인지 정한다.
    - 웹: oauth2Login() 기반 OIDC 로그인
    - 앱/토큰 요청: oauth2ResourceServer().jwt() 기반 Bearer Token 검증
    5. 로그아웃을 어떻게 처리할지 정한다.
    - 웹: Gateway 세션 종료 + Keycloak OIDC 로그아웃
    - 앱/토큰 요청: 서버 세션이 없으므로 기본적으로 클라이언트 토큰 삭제 또는 별도 revoke 정책 사용
    6. CSRF/CORS를 어떻게 처리할지 정한다.
    - 웹: JSESSIONID 쿠키 기반이므로 운영 전에는 CSRF 방어를 다시 적용해야 한다.
      현재는 Swagger Try it out 기반 MSA API 검증을 위해 임시로 비활성화한다.
    - 앱/토큰 요청: Authorization 헤더 기반 stateless 인증이므로 CSRF 비활성화
    7. 세션을 쓸지, JWT만 쓸지 정한다.
    - 웹: IF_REQUIRED, JSESSIONID 세션 사용
    - 앱/토큰 요청: STATELESS, 세션 미사용
    8. 인증 실패 / 권한 실패 시 어떻게 응답할지 정한다.
    - 웹: 로그인 페이지 또는 프론트 경로로 리다이렉트
    - 앱/토큰 요청: 401/403 JSON 응답이 적합하다.

    이 Bean들을 등록하면 Spring Boot의 기본 SecurityFilterChain 대신
    내가 직접 정의한 보안 규칙이 적용된다.
    */

    // 모바일 전용
    @Bean
    @Order(1)
    public SecurityFilterChain bearerTokenSecurityFilterChain(
            HttpSecurity http,
            CorsConfigurationSource corsConfigurationSource,
            ApiExceptionAuthenticationEntryPoint authenticationEntryPoint,
            ApiExceptionAccessDeniedHandler accessDeniedHandler
    ) throws Exception {
        return http
                // 모바일 전용 - Bearer 토큰
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
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )

                // Authorization: Bearer 형식으로 전달된 Keycloak Access Token을 검증한다.
                // 이 설정은 모바일 로그인 자체를 처리하는 것이 아니라,
                // 모바일 앱이 이미 발급받아 보낸 JWT를 API 요청마다 검증하는 Resource Server 설정이다.
                // 검증에 성공하면 해당 요청 동안 사용할 JwtAuthenticationToken이 생성된다.
                // Authorization: Bearer <JWT>
                // Keycloak issuer-uri 기준으로 JWT 검증
                // 서명 검증
                // 만료 시간 검증
                // issuer 검증
                // JwtAuthenticationToken 생성
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                )
                .build();
    }

    // 웹 전용
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http,
                                                      LogoutSuccessHandler oidcLogoutSuccessHandler,
                                                      OidcLoginSuccessHandler oidcLoginSuccessHandler,
                                                      CorsConfigurationSource corsConfigurationSource,
                                                      SessionRegistry sessionRegistry
    ) throws Exception {

        return http
                // 1. 어떤 URL은 로그인 없이 허용할지 정한다. -> 에러
                // 2. 어떤 URL은 로그인 없이 허용할지 정한다. -> 나머지 전부
                // auth -> Spring Security가 넘겨준 URL 인가 규칙 설정 객체
                .authorizeHttpRequests(auth -> auth
                                // 아래는 로그인 없이 허용
                                .requestMatchers(
//                                "/api/auth/me",
//                                "/error",
//                                "/api/v1/items/**",
//                                "/api/v2/items/**",
//                                "/swagger-ui/**",
//                                "/swagger-ui.html",
//                                "/v3/api-docs/**",
//                                "/item/swagger-ui/**",
//                                "/item/v3/api-docs/**",
//                                "/item/api/v1/items/**",
//                                "/item/api/v2/items/**",
//                                "/health"
                                        "/**"
                                ).permitAll()
                                // 나머지는 전부 로그인을 거쳐야함
                                // /api/csrf는 로그인 후 호출한다.
                                // anyRequest().authenticated()에 의해 인증된 사용자만 CSRF 토큰을 받을 수 있다.
                                .anyRequest().authenticated()
                )


                // 3. 어떤 URL은 특정 Role이 있어야 접근 가능한지 정한다.
                // MSA에서 Role 검사는 각 서비스 내에서 진행한다. -> Gateway에서는 Role 기반 인가를 하지 않는다.


                // 4. 로그인 방식은 무엇인지 정한다.
                // Keycloak을 이용하는데,
                // Spring 서버가 OAuth2/OIDC Client가 돼서,
                // 사용자를 Keycloak 로그인 페이지로 리다이렉트하고,
                // 로그인 성공 후 callback을 받아 세션을 만드는 기능
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oidcLoginSuccessHandler)
                )
                // 5. 로그아웃은 어떻게 할지 정한다.
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
                // Gateway는 웹 브라우저와 JSESSIONID 세션 쿠키를 사용하므로
                // 운영 기준으로는 CSRF 보호가 필요하다.
                //
                // 다만 현재는 각 MSA API를 Swagger Try it out으로 검증하는 개발 단계다.
                // Try it out까지 허용하려고 /item/**, /sales/** 같은 주요 MSA 라우트를
                // CSRF 예외로 넓게 빼면 보호 범위가 불명확해진다.
                //
                // 그래서 개발 기간에는 전체 비활성화 상태를 명시적으로 유지한다.
                // 운영 전에는 CookieCsrfTokenRepository 기반 CSRF 보호를 다시 활성화해야 한다.
                .csrf(AbstractHttpConfigurer::disable)

                // 7. 세션을 쓸지, JWT만 쓸지 정한다.
                // 현재 oauth2Login을 사용하면서
                // 웹 브라우저는 Gateway 세션 + JSESSIONID 쿠키를 사용한다.
                // SessionCreationPolicy.IF_REQUIRED는 기본값에 가깝지만,
                // oauth2Login 기반 웹 세션 사용 의도를 명확히 하기 위해 명시한다. (SessionCreationPolicy.IF_REQUIRED)
                // 로그인 성공 시 세션 ID를 변경하여 세션 고정 공격을 방어한다.
                // changeSessionId()도 기본 전략에 가깝지만 보안 의도를 명시한다. (sessionFixation.changeSessionId())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::changeSessionId)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                        .expiredUrl("http://localhost:5173/login?expired=true")
                        .sessionRegistry(sessionRegistry)
                )

                // 8. 인증 실패 / 권한 실패 시 어떻게 응답할지 정한다.
                // 웹 브라우저 요청은 OAuth2 로그인/리다이렉트 흐름을 유지한다.
                // Bearer 토큰 요청의 401/403 JSON 응답은 bearerTokenSecurityFilterChain에서 처리한다.
                .build();
    }


    // cors 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        // CORS 정책 객체를 생성한다.
        CorsConfiguration config = new CorsConfiguration();


        // 요청을 허용할 프론트엔드 Origin 지정
        // Cross-Origin 요청에서는 쿠키를 기본적으로 안 보내지만
        // JSESSIONID 쿠키를 포함한 요청을 허용해야 하므로 allowCredentials(true)를 사용한다.
        // 이 경우 "*" 전체 허용은 사용할 수 없고, 정확한 Origin을 지정해야 한다.
        config.setAllowedOrigins(List.of(
                "http://localhost:5173"
        ));


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
        config.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "X-XSRF-TOKEN"
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
       현재 로그인된 사용자들의 세션 정보를 추적하기 위한 저장소 Bean
       maximumSessions(1) 설정과 함께 사용되며,
       어떤 principal이 어떤 세션을 가지고 있는지를 관리한다.
       또한 커스텀 로그인 성공 핸들러에서
       sessionRegistry.getAllPrincipals,
       sessionRegistry.getAllSessions를 통해
       기존 로그인 세션을 찾아 만료시키는 데 사용한다.
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /*
       HttpSession의 생성/소멸/만료 이벤트를 Spring Security에 전달하는 Bean
       SessionRegistry는 현재 살아있는 세션 정보를 관리해야 하는데,
       로그아웃이나 세션 만료가 발생했을 때 그 정보를 정리하려면
       서블릿 컨테이너의 세션 이벤트를 알아야 한다.
       이 Bean을 등록하면 세션이 사라졌을 때
       SessionRegistry 쪽에도 해당 세션 만료/삭제 이벤트가 전달된다.
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }


}
