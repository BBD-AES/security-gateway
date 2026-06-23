package com.bbd.securitygateway.auth.adapter.in.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/*
 OAuth2/OIDC 로그인 성공 후 실행되는 보안 정책 핸들러.

 SecurityConfig는 필터체인 배선만 담당하고,
 같은 Keycloak 사용자로 이미 로그인된 기존 세션을 만료시키는 정책은
 이 Adapter에서 별도로 수행한다.

 목적:
 - 같은 Keycloak 사용자로 이미 로그인된 기존 세션이 있으면 기존 세션을 만료시킨다.
 - 새로 로그인한 현재 세션만 유지한다.
 - 로그인 성공 후 main 페이지로 이동시킨다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OidcLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final SessionRegistry sessionRegistry;
    private final OidcUserSubjectExtractor subjectExtractor;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    // 로그인 성공/오류 리다이렉트 목적지(환경별 설정). @RequiredArgsConstructor 는 final 만 받으므로 필드 주입.
    @Value("${app.frontend.base-url}")
    private String frontendBaseUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        // 현재 로그인 요청의 HttpSession을 가져온다.
        // false는 이미 세션이 있으면 가져오고, 없으면 null 반환이라는 의미다.
        HttpSession session = request.getSession(false);

        // 정상적인 OAuth2/OIDC 로그인 성공 흐름에서는 HttpSession이 이미 존재해야 한다.
        // 세션이 없다면 인증 흐름이 비정상적으로 깨진 상황이므로 새 세션을 만들지 않고 다시 로그인시킨다.
        if (session == null) {
            log.warn(
                    "OAuth2 로그인은 성공했지만 HttpSession이 없습니다. method={}, uri={}",
                    request.getMethod(),
                    request.getRequestURI()
            );
            response.sendRedirect(frontendBaseUrl + "/login?error=session");
            return;
        }

        String currentSessionId = session.getId();
        String currentUserKey = extractUserKey(authentication.getPrincipal());

        // 중복 세션 로그인 흐름
        expireOtherSessionsOfSameUser(currentSessionId, currentUserKey);

        // 로그인 성공 후 main 페이지로 리다이렉트한다.
        // defaultSuccessUrl 대신 직접 RedirectStrategy를 사용하는 이유는
        // 위의 기존 세션 만료 로직을 실행한 뒤 원하는 위치로 보내기 위해서다.
        redirectStrategy.sendRedirect(request, response, frontendBaseUrl + "/main");
    }

    private void expireOtherSessionsOfSameUser(String currentSessionId, String currentUserKey) {
        // SessionRegistry에 등록된 모든 principal을 순회한다.
        // principal은 Spring Security가 세션에 저장한 인증 사용자 객체다.
        sessionRegistry.getAllPrincipals().forEach(principal -> {
            String userKey = extractUserKey(principal);

            if (currentUserKey.equals(userKey)) {
                // 동일한 세션이 존재한다면 기존 세션을 만료 처리한다.
                expireSessionsExceptCurrent(principal, currentSessionId);
            }
        });
    }

    private void expireSessionsExceptCurrent(Object principal, String currentSessionId) {
        // false는 이미 만료 처리된 세션은 제외하고 조회한다는 의미다.
        sessionRegistry.getAllSessions(principal, false).forEach(sessionInformation -> {
            if (!sessionInformation.getSessionId().equals(currentSessionId)) {
                // 실제 세션 객체를 즉시 삭제한다기보다는,
                // Spring Security가 이후 해당 세션 요청을 만료된 세션으로 인식하게 한다.
                sessionInformation.expireNow();

                // 세션 ID는 인증 정보로 취급될 수 있으므로 전체 값을 남기지 않고 일부만 마스킹해서 기록한다.
                log.info(
                        "중복 OAuth2 로그인으로 기존 세션을 만료 처리했습니다. currentSession={}, expiredSession={}",
                        maskForLog(currentSessionId),
                        maskForLog(sessionInformation.getSessionId())
                );
            }
        });
    }

    private String extractUserKey(Object principal) {
        return subjectExtractor.extract(principal)
                .orElseThrow(() -> unexpectedPrincipal(principal));
    }

    private IllegalStateException unexpectedPrincipal(Object principal) {
        // 보안 세션 판단 로직과 직결되는 비정상 상태이므로 principal 타입만 로그로 남긴다.
        log.error(
                "OAuth2 세션 비교 중 예상하지 못한 principal 타입이 감지되었습니다. principalType={}",
                principal == null ? "null" : principal.getClass().getName()
        );
        return new IllegalStateException(
                "OIDC 로그인에서 예상하지 않은 principal 타입입니다: "
                        + (principal == null ? "null" : principal.getClass().getName())
        );
    }

    /*
     세션 ID는 쿠키 인증에 쓰이는 민감한 값이므로 로그에 전체를 남기지 않는다.
     운영 추적에 필요한 최소한의 구분만 가능하도록 앞/뒤 일부만 남기고 마스킹한다.
     */
    private String maskForLog(String value) {
        if (value == null || value.isBlank()) {
            return "blank";
        }

        if (value.length() <= 8) {
            return "****";
        }

        return value.substring(0, 4) + "..." + value.substring(value.length() - 4);
    }
}
