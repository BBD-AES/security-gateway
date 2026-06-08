package com.bbd.securitygateway.global.error.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

/*
 Gateway에서 사용할 비즈니스 에러 코드.

 ProblemDetail 응답에서:
 - status  -> HTTP 상태 코드
 - title   -> code 값
 - detail  -> message 값
 으로 사용한다.
 */
@Getter
@AllArgsConstructor
public enum ErrorCode {

    /*
     인증되지 않은 사용자.

     예:
     - 로그인하지 않음
     - 세션 만료
     - 인증 정보 없음
     */
    AUTH_UNAUTHENTICATED(
            HttpStatus.UNAUTHORIZED,
            "AUTH001",
            "로그인이 필요합니다."
    ),

    /*
     인증은 되었지만 접근 권한이 없는 경우.
     */
    AUTH_FORBIDDEN(
            HttpStatus.FORBIDDEN,
            "AUTH002",
            "접근 권한이 없습니다."
    ),

    /*
     ERP 서비스 이용이 불가능한 사용자.

     예:
     - INACTIVE 사용자
     - PENDING 사용자
     */
    AUTH_USER_NOT_ACTIVE(
            HttpStatus.FORBIDDEN,
            "AUTH003",
            "BBD ERP를 이용할 수 없는 사용자입니다."
    ),

    /*
     서버가 처리하지 못하는 사용자 상태.

     예:
     - UserStatus enum에 새 값이 추가되었는데 Gateway에서 아직 처리하지 못하는 경우
     */
    AUTH_USER_STATUS_INVALID(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "AUTH004",
            "지원하지 않는 사용자 상태입니다."
    ),

    /*
     User Service 호출 실패.

     예:
     - User Service 장애
     - 네트워크 오류
     */
    UPSTREAM_USER_SERVICE_UNAVAILABLE(
            HttpStatus.SERVICE_UNAVAILABLE,
            "AUTH005",
            "사용자 서비스를 일시적으로 사용할 수 없습니다."
    ),

    /*
     User Service 응답 지연.
     */
    UPSTREAM_USER_SERVICE_TIMEOUT(
            HttpStatus.GATEWAY_TIMEOUT,
            "AUTH006",
            "사용자 서비스 응답이 지연되고 있습니다."
    ),

    /*
     처리되지 않은 서버 오류.
     */
    INTERNAL_ERROR(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "COMMON001",
            "일시적인 오류가 발생했습니다."
    );

    private final HttpStatus status;
    private final String code;
    private final String message;
}