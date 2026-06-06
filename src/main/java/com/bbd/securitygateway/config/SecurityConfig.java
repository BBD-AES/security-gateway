package com.bbd.securitygateway.config;

import jakarta.servlet.http.HttpSession;
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
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
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
    - 웹: JSESSIONID 쿠키 기반이므로 CSRF 방어 적용
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
    public SecurityFilterChain mobileSecurityFilterChain(
            HttpSecurity http,
            CorsConfigurationSource corsConfigurationSource
    ) throws Exception {
        return http
                // 모바일 전용 - Bearer 토큰
                .securityMatcher(request -> {
                    String authorization = request.getHeader("Authorization");
                    return authorization != null && authorization.startsWith("Bearer ");
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
                                                      ClientRegistrationRepository clientRegistrationRepository,
                                                      CorsConfigurationSource corsConfigurationSource,
                                                      SessionRegistry sessionRegistry
    ) throws Exception {

        CookieCsrfTokenRepository csrfTokenRepository =
                CookieCsrfTokenRepository.withHttpOnlyFalse();

        csrfTokenRepository.setCookiePath("/");


        return http
                // 1. 어떤 URL은 로그인 없이 허용할지 정한다. -> 에러
                // 2. 어떤 URL은 로그인 없이 허용할지 정한다. -> 나머지 전부
                // auth -> Spring Security가 넘겨준 URL 인가 규칙 설정 객체
                .authorizeHttpRequests(auth -> auth
                        // 아래는 로그인 없이 허용
                        .requestMatchers(
                                "/error",
                                "/api/v1/items/**",
                                "/api/v2/items/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**",
                                "/item/swagger-ui/**",
                                "/item/v3/api-docs/**",
                                "/item/api/v1/items/**",
                                "/item/api/v2/items/**",
                                "/health"
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
                        .successHandler(oauth2LoginSuccessHandler(sessionRegistry))
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
                        .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository))
                )


                // 6. CSRF/CORS는 어떻게 할지 정한다.
                // 1) CORS
                // 웹 브라우저는 Gateway와 origin이 다르면 CORS 설정이 필요하다.
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                // 2) CSRF
                // 웹은 세션 기반 CSRF 사용
                .csrf(csrf -> csrf
                        .csrfTokenRepository(csrfTokenRepository)
                )

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
                // 임시 생략
                .build();
    }


    // Gateway 로그아웃 성공 후 실행될 OIDC 로그아웃 핸들러를 생성한다.
    // 일반 logoutSuccessUrl은 Gateway 세션만 종료한 뒤 프론트로 이동하지만,
    // OidcClientInitiatedLogoutSuccessHandler는 Keycloak의 end_session_endpoint로
    // 브라우저를 redirect시켜 Keycloak SSO 세션까지 종료하도록 한다.
    private LogoutSuccessHandler oidcLogoutSuccessHandler(
            // Spring Security가 등록한 OAuth2/OIDC Client 정보 저장소
            // 여기에는 yml에 설정한 Keycloak client-id, issuer-uri 등이 들어 있다.
            // 이 정보를 이용해 Keycloak의 end_session_endpoint를 찾는다.
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        // OIDC RP-Initiated Logout을 처리하는 Spring Security 제공 핸들러
        // 로그아웃 성공 시 현재 사용자의 ID Token과 ClientRegistration 정보를 이용해서
        // Keycloak 로그아웃 URL을 생성한다.
        OidcClientInitiatedLogoutSuccessHandler handler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);

        // Keycloak 로그아웃이 끝난 뒤 최종적으로 돌아올 프론트엔드 주소를 지정한다.
        // 이 값은 Keycloak 로그아웃 URL의 post_logout_redirect_uri 파라미터로 사용된다.
        handler.setPostLogoutRedirectUri("http://localhost:5173/login");

        // Spring Security logout 설정의 logoutSuccessHandler에 넘길 핸들러 반환
        return handler;
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
       OAuth2/OIDC 로그인 성공 후 실행할 커스텀 성공 핸들러
       목적:
       - 같은 Keycloak 사용자로 이미 로그인된 기존 세션이 있으면 기존 세션을 만료시킨다.
       - 새로 로그인한 현재 세션만 유지한다.
       - 로그인 성공 후 main 페이지로 이동시킨다.
     */

    private AuthenticationSuccessHandler oauth2LoginSuccessHandler(SessionRegistry sessionRegistry) {
        return (request, response, authentication) -> {

            // 현재 로그인 요청의 HttpSession을 가져온다.
            // false는 이미 세션이 있으면 가져오고, 없으면 null 반환이라는 의미
            HttpSession session = request.getSession(false);


            // 정상적인 OAuth2/OIDC 로그인 성공 흐름에서는 HttpSession이 이미 존재해야 한다.
            // 세션이 없다면 OAuth2 AuthorizationRequest 저장/검증 또는 세션 인증 전략 흐름이 깨진 비정상 상태로 본다.
            // 따라서 새 세션을 만들어 계속 진행하지 않고, 다시 로그인하도록 돌려보낸다.
            if (session == null) {
                response.sendRedirect("http://localhost:5173/login?error=session");
                return;
            }


            // 현재 로그인에 사용되는 세션 ID
            String currentSessionId = session.getId();

            // 현재 로그인한 사용자의 고유 식별값을 추출한다.
            // OIDC 로그인에서는 Keycloak sub 값을 우선 사용한다.
            String currentUserKey = extractUserKey(authentication.getPrincipal());

            // SessionRegistry에 등록된 모든 principal을 순회한다.
            // principal은 Spring Security가 세션에 저장한 인증 사용자 객체다.
            sessionRegistry.getAllPrincipals().forEach(principal -> {

                // 기존 세션에 저장된 principal에서도 사용자 고유 식별값을 추출한다.
                String userKey = extractUserKey(principal);

                // 현재 로그인한 사용자와 같은 사용자라면
                if (currentUserKey.equals(userKey)) {

                    // 해당 principal이 가진 모든 세션을 조회한다.
                    // false는 이미 만료 처리된 세션은 제외하고 조회한다는 의미다.
                    sessionRegistry.getAllSessions(principal, false).forEach(sessionInformation -> {

                        // 현재 새로 로그인한 세션이 아닌 기존 세션이면
                        if (!sessionInformation.getSessionId().equals(currentSessionId)) {

                            // 기존 세션을 만료 처리한다.
                            // 실제 세션 객체를 즉시 삭제한다기보다는,
                            // Spring Security가 이후 해당 세션 요청을 만료된 세션으로 인식하게 한다.
                            sessionInformation.expireNow();
                        }
                    });
                }
            });
            // 로그인 성공 후 main 페이지로 리다이렉트한다.
            // defaultSuccessUrl 대신 직접 RedirectStrategy를 사용하는 이유는
            // 위의 기존 세션 만료 로직을 실행한 뒤 원하는 위치로 보내기 위해서다.
            RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
            redirectStrategy.sendRedirect(request, response, "http://localhost:5173/main");
        };
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


    /*
       principal 객체에서 같은 사용자 여부를 판단할 고유값을 추출한다.
       OAuth2/OIDC 로그인에서는 로그인 성공 시마다 OidcUser/DefaultOidcUser principal 객체가 새로 생성된다.
       Keycloak의 sub 같은 안정적인 사용자 고유값을 기준으로 비교한다.
       이 메서드는 커스텀 로그인 성공 핸들러에서
       현재 로그인 사용자와 기존 세션 사용자들이 같은 사람인지 비교할 때 사용된다.
     */
    private String extractUserKey(Object principal) {
        // 현재 Gateway는 Keycloak OIDC 로그인을 사용한다.
        // OIDC 로그인 성공 시 principal은 OidcUser이며,
        // sub는 Keycloak Realm 내 사용자를 식별하는 안정적인 고유 ID다.
        if (principal instanceof OidcUser oidcUser) {
            return oidcUser.getSubject(); // Keycloak sub
        }

        // 현재 인증 구조에서는 OidcUser 외 principal은 예상하지 않는다.
        // 예상하지 않은 principal로 같은 사용자 비교를 계속하면
        // 잘못된 세션 만료가 발생할 수 있으므로 실패 처리한다.
        throw new IllegalStateException(
                "OIDC 로그인에서 예상하지 않은 principal 타입입니다: "
                        + principal.getClass().getName()
        );
    }
}
