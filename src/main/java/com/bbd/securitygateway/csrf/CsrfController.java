package com.bbd.securitygateway.csrf;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// /api/csrf가 있으면
// 프론트가 CSRF 토큰을 미리 확실하게 받아올 수 있다.

// 반대로 api/csrf가 없으면
//→ CSRF 토큰이 언제 쿠키로 내려올지 애매해서 첫 POST 요청에서 403이 날 수 있다.

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