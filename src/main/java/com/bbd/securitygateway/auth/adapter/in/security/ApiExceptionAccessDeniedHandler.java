package com.bbd.securitygateway.auth.adapter.in.security;

import com.bbd.securitygateway.global.error.ApiException;
import com.bbd.securitygateway.global.error.dto.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

/*
 Bearer 토큰 요청에서 인가 실패가 발생했을 때 실행되는 핸들러.

 인증 진입점과 마찬가지로 Spring Security 필터 단계의 예외를
 ApiException으로 변환해 Gateway 공통 에러 응답 컨벤션을 유지한다.
 */
@Component
public class ApiExceptionAccessDeniedHandler implements AccessDeniedHandler {

    private final HandlerExceptionResolver exceptionResolver;

    public ApiExceptionAccessDeniedHandler(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver
    ) {
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) {
        exceptionResolver.resolveException(
                request,
                response,
                null,
                new ApiException(ErrorCode.AUTH_FORBIDDEN)
        );
    }
}
