package com.bbd.securitygateway.auth.adapter.in.security;

import com.bbd.securitygateway.config.FrontendProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 동시 로그인(maximumSessions=1, maxSessionsPreventsLogin=false)으로 만료된 기존 세션이
 * 다시 요청할 때의 처리 전략.
 *
 * 문제: 기본 {@code .expiredUrl(...)} 는 만료 세션의 '모든' 요청을 프론트 만료 페이지로 302 리다이렉트한다.
 *       SPA(fetch/XHR)는 그 302를 따라가 HTML(200)을 받으므로 만료를 감지하지 못하고 화면이 멈춘다.
 *
 * 해결:
 *  - API/XHR 요청(Accept: application/json · /api/** · X-Requested-With) → 401 JSON.
 *    프론트 apiFetch 가 401 을 받아 OIDC 로그인으로 리다이렉트한다.
 *  - 일반 브라우저 내비게이션 → 기존대로 프론트 만료 페이지로 302 리다이렉트.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ApiAwareSessionExpiredStrategy implements SessionInformationExpiredStrategy {

    private final FrontendProperties frontendProperties;

    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException {
        HttpServletRequest request = event.getRequest();
        HttpServletResponse response = event.getResponse();

        if (isApiRequest(request)) {
            log.info("만료 세션 API 요청 → 401(SESSION_EXPIRED). uri={}", request.getRequestURI());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                    "{\"code\":\"SESSION_EXPIRED\",\"message\":\"다른 곳에서 로그인되어 세션이 만료되었습니다.\"}");
        } else {
            log.info("만료 세션 내비게이션 → 만료 페이지 리다이렉트. uri={}", request.getRequestURI());
            response.sendRedirect(frontendProperties.loginExpiredUrl());
        }
    }

    /** SPA 의 게이트웨이 프록시 호출은 prefix 라우팅이라 경로가 /sales·/inventory 등이고, Accept=application/json 이다. */
    private boolean isApiRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri != null && uri.startsWith("/api/")) {
            return true;
        }
        if ("XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"))) {
            return true;
        }
        String accept = request.getHeader("Accept");
        return accept != null && accept.contains("application/json");
    }
}
