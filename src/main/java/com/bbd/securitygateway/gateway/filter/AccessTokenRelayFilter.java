package com.bbd.securitygateway.gateway.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/*
 Gateway 웹 세션에 저장된 OAuth2 Access Token을
 하위 MSA 요청의 Authorization 헤더로 전달하기 위한 필터.

 현재 웹 구조:
 - 브라우저는 Access Token을 직접 들고 있지 않는다.
 - 브라우저는 Gateway에 JSESSIONID 세션 쿠키로 요청한다.
 - Gateway는 oauth2Login 과정에서 OAuth2AuthorizedClient를 저장한다.
 - OAuth2AuthorizedClient 안에 Keycloak Access Token이 들어 있다.

 이 필터의 역할:
 - 이미 Authorization: Bearer 헤더가 있는 요청은 그대로 둔다.
   예: Sales -> Gateway -> Item 같은 서비스 간 호출

 - Authorization 헤더가 없고, 현재 요청이 웹 세션 로그인 사용자라면
   OAuth2AuthorizedClient에서 Access Token을 꺼내
   Authorization: Bearer <access-token> 헤더를 새로 제공한다.

 - 인증되지 않은 요청이면 Authorization 헤더를 새로 추가하지 않는다.

 최종 인가 구조:
 - Gateway는 Access Token Relay만 수행한다.
 - 각 MSA는 Access Token을 직접 검증한다.
 - 각 MSA는 JWT sub를 기준으로 Redis UserSnapshot을 조회한다.
 - Redis에 없으면 User Service를 조회해 Snapshot을 적재한다.

 이 필터는 Spring SecurityFilterChain 안에서만 실행되도록 SecurityConfig에서 등록한다.
 @Component로 Bean 등록하되, 일반 Servlet Filter 자동 등록은 FilterRegistrationBean으로 비활성화한다.
 */
@Component
public class AccessTokenRelayFilter extends OncePerRequestFilter {

    private static final String CLIENT_REGISTRATION_ID = "keycloak";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    public AccessTokenRelayFilter(OAuth2AuthorizedClientRepository authorizedClientRepository) {
        this.authorizedClientRepository = authorizedClientRepository;
    }

    /*
     요청당 한 번 실행되는 실제 필터 로직.

     처리 순서:
     1. 요청에 이미 Authorization: Bearer 헤더가 있으면 그대로 다음 필터로 넘긴다.
     2. Authorization 헤더가 없으면 Gateway 웹 세션에서 Access Token을 꺼낸다.
     3. Access Token이 있으면 Authorization: Bearer <token> 헤더가 있는 것처럼 wrapper로 감싼다.
     4. Access Token이 없으면 Authorization 헤더 없이 그대로 진행한다.
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        if (hasBearerToken(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String accessToken = extractAccessToken(request);

        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        HttpServletRequest wrappedRequest =
                new AuthorizationHeaderRequestWrapper(request, accessToken);

        filterChain.doFilter(wrappedRequest, response);
    }

    /*
     현재 요청에 이미 Authorization: Bearer 헤더가 있는지 확인한다.

     이미 Bearer 토큰이 있다면 Gateway가 덮어쓰지 않는다.
     이유:
     - 모바일/앱 요청은 클라이언트가 직접 Bearer 토큰을 보낼 수 있다.
     - Sales -> Gateway -> Item 같은 서비스 간 요청도 Bearer 토큰을 이미 들고 올 수 있다.
     - 이 경우 기존 토큰을 유지하는 것이 맞다.
     */
    private boolean hasBearerToken(HttpServletRequest request) {
        String authorization = request.getHeader(AUTHORIZATION_HEADER);

        return authorization != null
                && authorization.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length());
    }

    /*
     Gateway 웹 세션에 저장된 OAuth2AuthorizedClient에서 Access Token을 꺼낸다.

     oauth2Login 성공 후 Spring Security는 OAuth2AuthorizedClient를 저장한다.
     이 객체 안에 Keycloak Access Token이 들어 있다.

     인증되지 않은 요청이면 null을 반환한다.
     Access Token을 찾을 수 없어도 null을 반환한다.
     */
    private String extractAccessToken(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder
                .getContext()
                .getAuthentication();

        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return null;
        }

        OAuth2AuthorizedClient authorizedClient =
                authorizedClientRepository.loadAuthorizedClient(
                        CLIENT_REGISTRATION_ID,
                        authentication,
                        request
                );

        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            return null;
        }

        return authorizedClient.getAccessToken().getTokenValue();
    }

    /*
     원본 HttpServletRequest에 Authorization 헤더가 있는 것처럼 보이게 하는 wrapper.

     실제 HttpServletRequest의 헤더는 직접 수정할 수 없다.
     따라서 request를 감싸고, getHeader(), getHeaders(), getHeaderNames()만 오버라이드한다.

     뒤쪽 Gateway 라우팅 로직은 이 wrapper를 통해
     Authorization: Bearer <access-token> 헤더를 읽게 된다.
     */
    private static class AuthorizationHeaderRequestWrapper extends HttpServletRequestWrapper {

        private final String accessToken;

        private AuthorizationHeaderRequestWrapper(HttpServletRequest request, String accessToken) {
            super(request);
            this.accessToken = accessToken;
        }

        /*
         단일 헤더 조회.

         Authorization 헤더를 조회하면
         Gateway 웹 세션에서 꺼낸 Access Token을 Bearer 형식으로 반환한다.
         */
        @Override
        public String getHeader(String name) {
            if (AUTHORIZATION_HEADER.equalsIgnoreCase(name)) {
                return BEARER_PREFIX + accessToken;
            }

            return super.getHeader(name);
        }

        /*
         같은 이름의 여러 헤더 값을 조회할 때 사용된다.

         Authorization 헤더는 Gateway가 만든 Bearer 토큰 하나만 반환한다.
         */
        @Override
        public Enumeration<String> getHeaders(String name) {
            if (AUTHORIZATION_HEADER.equalsIgnoreCase(name)) {
                return Collections.enumeration(List.of(BEARER_PREFIX + accessToken));
            }

            return super.getHeaders(name);
        }

        /*
         전체 헤더 이름 목록 조회.

         원본 요청 헤더 이름을 유지하되,
         Authorization 헤더가 목록에 포함되도록 추가한다.
         */
        @Override
        public Enumeration<String> getHeaderNames() {
            Set<String> headerNames = new LinkedHashSet<>();

            Enumeration<String> originalHeaderNames = super.getHeaderNames();

            while (originalHeaderNames.hasMoreElements()) {
                String headerName = originalHeaderNames.nextElement();

                if (!AUTHORIZATION_HEADER.equalsIgnoreCase(headerName)) {
                    headerNames.add(headerName);
                }
            }

            headerNames.add(AUTHORIZATION_HEADER);

            return Collections.enumeration(headerNames);
        }
    }
}