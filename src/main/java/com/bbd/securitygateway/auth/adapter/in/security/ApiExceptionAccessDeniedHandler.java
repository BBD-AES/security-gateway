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

    /*
     Spring Security 필터 단계에서 발생한 인가 실패는 컨트롤러까지 도달하지 않는다.
     따라서 직접 응답을 만들지 않고, HandlerExceptionResolver를 통해
     ApiException을 GlobalExceptionHandler로 넘겨 공통 에러 응답 형식을 유지한다.
     */
    private final HandlerExceptionResolver exceptionResolver;

    public ApiExceptionAccessDeniedHandler(
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver
    ) {
        this.exceptionResolver = exceptionResolver;
    }

    /*
     인증은 되었지만 접근 권한이 부족할 때 호출된다.
     예: 필요한 role/authority가 없거나, Security 인가 규칙에서 접근이 거부된 경우.
     */
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) {
        // Security 인가 실패를 프로젝트 공통 403 예외로 변환해 공통 예외 처리기에 위임한다.
        exceptionResolver.resolveException(
                request,
                response,
                null,
                new ApiException(ErrorCode.AUTH_FORBIDDEN)
        );
    }
}
