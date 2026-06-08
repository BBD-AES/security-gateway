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
    - 예: 인증 실패, 권한 없음, User Service 장애, 지원하지 않는 사용자 상태 등
    - ErrorCode를 가지고 있으며, ErrorCode 기준으로 ProblemDetail을 생성한다.

 2. Exception
    - 별도로 처리하지 못한 모든 서버 예외
    - 500 INTERNAL_ERROR로 변환한다.
    - 내부 예외 메시지, 스택트레이스, SQL 메시지 등은 클라이언트에 노출하지 않는다.

 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    /*
     Gateway에서 직접 던진 ApiException을 처리한다.

     ApiException은 내부에 ErrorCode를 가지고 있다.
     ErrorCode에는 다음 정보가 들어 있다.

     - HTTP status
     - 비즈니스 에러 코드
     - 사용자에게 보여줄 메시지

     ApiException 생성 시 이미 ProblemDetail body가 만들어져 있으므로,
     여기서는 요청 경로만 추가한 뒤 응답으로 내려준다.

     예: throw new ApiException(ErrorCode.AUTH_UNAUTHENTICATED);

     응답 예:
     {
       "type": "about:blank",
       "title": "AUTH001",
       "status": 401,
       "detail": "로그인이 필요합니다.",
       "instance": "/api/auth/me",
       "timestamp": "2026-06-08T17:20:31.123+09:00"
     }
     */
    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ProblemDetail> handleApiException(
            ApiException e,
            HttpServletRequest request
    ) {
        /*
         ApiException이 가지고 있는 ProblemDetail 본문을 꺼낸다.

         이 body에는 이미 다음 값이 들어 있다.
         - status
         - title
         - detail
         - timestamp
         */
        ProblemDetail body = e.getBody();

        /*
         ProblemDetail의 instance 필드에 실제 요청 URI를 넣는다.

         instance는 "어떤 요청에서 에러가 발생했는가"를 나타내는 표준 필드다.
         예: /api/auth/me
         */
        body.setInstance(URI.create(request.getRequestURI()));

        /*
         HTTP 응답 상태와 ProblemDetail body의 status를 일치시켜 응답한다.

         e.getStatusCode()는 ApiException 생성 시 ErrorCode에서 가져온 HTTP 상태다.
         */
        return ResponseEntity
                .status(e.getStatusCode())
                .body(body);
    }

    /*
     처리되지 않은 모든 예외를 처리한다.

     이 핸들러는 마지막 방어선 역할을 한다.
     ApiException으로 명시적으로 처리하지 않은 예외가 여기로 들어온다.

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

        /*
         ProblemDetail 표준 응답 본문을 생성한다.

         ProblemDetail.forStatus를 사용하면 status 필드가 설정된다.
         */
        ProblemDetail body = ProblemDetail.forStatus(errorCode.getStatus());

        /*
         title에는 비즈니스 에러 코드를 넣는다.

         팀 컨벤션상 title 필드는
         "Not Found" 같은 기본 문구가 아니라
         AUTH001, COMMON001 같은 에러 코드로 사용한다.
         */
        body.setTitle(errorCode.getCode());

        /*
         detail에는 사용자에게 보여줄 메시지를 넣는다.
         내부 예외 메시지 e.getMessage()를 넣지 않는다.
         */
        body.setDetail(errorCode.getMessage());

        // instance에는 에러가 발생한 요청 URI를 넣는다.
        body.setInstance(URI.create(request.getRequestURI()));

        /*
         ProblemDetail 확장 필드로 timestamp를 추가한다.
         setProperty로 넣은 값은 JSON 직렬화 시 최상위 필드로 펼쳐진다.
         */
        body.setProperty("timestamp", OffsetDateTime.now());

        // HTTP status와 body.status가 일치하도록 응답한다.
        return ResponseEntity
                .status(errorCode.getStatus())
                .body(body);
    }
}