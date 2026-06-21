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

    /*
     Spring Security 필터 단계에서 발생한 인증 실패는 컨트롤러까지 도달하지 않는다.
     따라서 직접 응답을 만들지 않고, HandlerExceptionResolver를 통해
     ApiException을 GlobalExceptionHandler로 넘겨 공통 에러 응답 형식을 유지한다.
     */
    private final HandlerExceptionResolver exceptionResolver;

    public ApiExceptionAuthenticationEntryPoint(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver
    ) {
        this.exceptionResolver = exceptionResolver;
    }

    /*
     Bearer 토큰 인증 실패 시 호출된다.
     예: 토큰 없음, 토큰 만료, JWT 형식 오류, 서명 검증 실패.
     */
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) {
        // 401 응답에서 Bearer 인증이 필요함을 클라이언트에게 알린다.
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

        // Security 인증 실패를 프로젝트 공통 401 예외로 변환해 공통 예외 처리기에 위임한다.
        exceptionResolver.resolveException(
                request,
                response,
                null,
                new ApiException(ErrorCode.AUTH_UNAUTHENTICATED)
        );
    }
}
