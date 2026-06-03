package com.bbd.securitygateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

// SecurityConfig 파일: 이 서버로 들어오는 HTTP 요청을 Spring Security가 어떻게 처리할지 정하는 파일

// Spring Bean 설정 클래스
@Configuration
public class SecurityConfig {

    // 1. 어떤 URL은 로그인 없이 허용할지 정한다.
    // 2. 어떤 URL은 로그인해야 접근 가능한지 정한다.
    // 3. 어떤 URL은 특정 Role이 있어야 접근 가능한지 정한다.
    // 4. 로그인 방식은 무엇인지 정한다.
    // 5. 로그아웃은 어떻게 할지 정한다.
    // 6. CSRF/CORS는 어떻게 할지 정한다.
    // 7. 세션을 쓸지, JWT만 쓸지 정한다.
    // 8. 인증 실패 / 권한 실패 시 어떻게 응답할지 정한다.
    // 이 Bean을 등록하면 Spring Boot의 기본 SecurityFilterChain 대신
    // 내가 직접 정의한 보안 규칙이 적용된다.


    // 웹
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   CorsConfigurationSource corsConfigurationSource
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
                        .requestMatchers("/error").permitAll()
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
                        .defaultSuccessUrl("http://localhost:5173/main", true)
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
                        .logoutSuccessUrl("http://localhost:5173/login")
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
                )

                // 8. 인증 실패 / 권한 실패 시 어떻게 응답할지 정한다.
                // 임시 생략
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
}
