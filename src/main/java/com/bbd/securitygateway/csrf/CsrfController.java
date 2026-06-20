package com.bbd.securitygateway.csrf;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// CSRF 보호를 다시 활성화할 때 프론트가 토큰을 초기화하기 위한 API.
//
// 현재 개발 기간에는 Gateway CSRF를 비활성화해 두었으므로 이 API가 실질적으로 사용되지 않는다.
// 운영 전 CookieCsrfTokenRepository 기반 CSRF 보호를 다시 켜면,
// 프론트는 이 엔드포인트를 먼저 호출해 XSRF-TOKEN 쿠키를 받고
// 이후 상태 변경 요청에 X-XSRF-TOKEN 헤더를 함께 보내면 된다.

@RestController
public class CsrfController {

    // 프론트가 CSRF 토큰을 초기화하기 위해 호출하는 API
    // 이 파라미터를 받으면 Spring Security가 CsrfToken을 생성/조회한다.
    // CookieCsrfTokenRepository 사용 시 XSRF-TOKEN 쿠키가 응답에 내려간다.
    @GetMapping("/api/csrf")
    public CsrfToken csrf(CsrfToken csrfToken) {
        return csrfToken;
    }
}
