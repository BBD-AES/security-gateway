package com.bbd.securitygateway.auth.adapter.in.security;

import com.bbd.securitygateway.config.FrontendProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.stereotype.Component;

import java.io.IOException;

/*
 OAuth2/OIDC 로그인 성공 후 실행되는 보안 정책 핸들러.

 SecurityConfig는 필터체인 배선만 담당하고,
 같은 Keycloak 사용자로 이미 로그인된 기존 세션을 만료시키는 정책은
 maximumSessions(1)에서 일관되게 수행한다.

 목적:
 - Spring Session Redis 인덱스가 Keycloak sub 기준으로 세션을 찾을 수 있게 principal name을 저장한다.
 - 로그인 성공 후 main 페이지로 이동시킨다.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OidcLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final OidcUserSubjectExtractor subjectExtractor;
    private final FrontendProperties frontendProperties;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

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
            response.sendRedirect(frontendProperties.loginSessionErrorUrl());
            return;
        }

        String currentUserKey = extractUserKey(authentication.getPrincipal());
        session.setAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, currentUserKey);

        // 로그인 성공 후 main 페이지로 리다이렉트한다.
        // defaultSuccessUrl 대신 직접 RedirectStrategy를 사용해 프론트 URL 설정을 한 곳에서 재사용한다.
        redirectStrategy.sendRedirect(request, response, frontendProperties.mainUrl());
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
}
