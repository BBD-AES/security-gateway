package com.bbd.securitygateway.auth.adapter.in.security;

import com.bbd.securitygateway.global.error.ApiException;
import com.bbd.securitygateway.global.error.dto.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

/*
 Bearer 토큰 요청에서 인증 실패가 발생했을 때 실행되는 진입점.

 Spring Security 필터 단계에서 발생한 401은 컨트롤러까지 도달하지 않으므로,
 HandlerExceptionResolver에 ApiException을 넘겨 공통 GlobalExceptionHandler가
 같은 ProblemDetail 응답 형식으로 처리하게 한다.
 */
@Component
public class ApiExceptionAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final HandlerExceptionResolver exceptionResolver;

    public ApiExceptionAuthenticationEntryPoint(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver
    ) {
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) {
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        exceptionResolver.resolveException(
                request,
                response,
                null,
                new ApiException(ErrorCode.AUTH_UNAUTHENTICATED)
        );
    }
}
