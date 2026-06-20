package com.bbd.securitygateway.global.error.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum ErrorCode {

    AUTH_UNAUTHENTICATED(
            HttpStatus.UNAUTHORIZED,
            "AUTH001",
            "로그인이 필요합니다."
    ),

    AUTH_FORBIDDEN(
            HttpStatus.FORBIDDEN,
            "AUTH002",
            "접근 권한이 없습니다."
    ),

    INTERNAL_ERROR(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "COMMON001",
            "일시적인 오류가 발생했습니다."
    );

    private final HttpStatus status;
    private final String code;
    private final String message;
}
