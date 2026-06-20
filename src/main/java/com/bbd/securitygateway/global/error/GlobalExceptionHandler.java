package com.bbd.securitygateway.global.error;

import com.bbd.securitygateway.global.error.dto.ErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;
import java.time.OffsetDateTime;

/*
 전역 예외 처리기.

 Gateway에서 발생하는 예외 응답 형식을 Spring ProblemDetail로 통일한다.
 별도의 ErrorResponse DTO를 만들지 않고, Spring 표준 ProblemDetail을 사용한다.

 ProblemDetail 기본 필드:
 - status   : HTTP 상태 코드
 - title    : 비즈니스 에러 코드
 - detail   : 사용자에게 보여줄 메시지
 - instance : 에러가 발생한 요청 경로

 추가 확장 필드:
 - timestamp : 에러 발생 시각

 처리 대상:
 1. ApiException
    - Gateway에서 의도적으로 발생시킨 비즈니스 예외
    - ErrorCode 기준으로 ProblemDetail을 생성한다.

 2. Exception
    - 별도로 처리하지 못한 모든 서버 예외
    - 500 INTERNAL_ERROR로 변환한다.
    - 내부 예외 메시지, 스택트레이스, SQL 메시지 등은 클라이언트에 노출하지 않는다.

 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    /*
     Gateway에서 직접 던진 ApiException을 처리한다.

     컨트롤러/서비스 계층의 비즈니스 예외는 이 팀 공통 컨벤션을 따른다.
     Security Filter 단계의 인증/인가 실패도 HandlerExceptionResolver를 통해
     ApiException으로 이 핸들러에 위임한다.
     */
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ProblemDetail> handleApiException(
            ApiException e,
            HttpServletRequest request
    ) {
        ProblemDetail body = e.getBody();
        body.setInstance(URI.create(request.getRequestURI()));

        return ResponseEntity
                .status(e.getStatusCode())
                .body(body);
    }

    /*
     처리되지 않은 모든 예외를 처리한다.

     이 핸들러는 마지막 방어선 역할을 한다.

     예:
     - NullPointerException
     - 예상하지 못한 RuntimeException
     - 외부 라이브러리 내부 오류
     - 코드 버그로 인한 예외

     클라이언트에는 내부 예외 메시지를 그대로 내려주지 않는다.
     예외 메시지에는 SQL, 파일 경로, 내부 클래스명, 스택트레이스 등
     민감한 정보가 포함될 수 있기 때문이다.

     따라서 응답은 공통 INTERNAL_ERROR 메시지로 통일한다.
     실제 예외 내용은 서버 로그에서 확인해야 한다.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleException(
            Exception e,
            HttpServletRequest request
    ) {
        // 처리되지 않은 서버 오류는 공통 INTERNAL_ERROR 코드로 변환한다.
        ErrorCode errorCode = ErrorCode.INTERNAL_ERROR;
        ProblemDetail body = ProblemDetail.forStatus(errorCode.getStatus());
        body.setTitle(errorCode.getCode());
        body.setDetail(errorCode.getMessage());
        body.setInstance(URI.create(request.getRequestURI()));
        body.setProperty("timestamp", OffsetDateTime.now());

        // HTTP status와 body.status가 일치하도록 응답한다.
        return ResponseEntity
                .status(errorCode.getStatus())
                .body(body);
    }
}