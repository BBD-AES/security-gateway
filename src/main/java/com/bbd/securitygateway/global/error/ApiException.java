package com.bbd.securitygateway.global.error;

import com.bbd.securitygateway.global.error.dto.ErrorCode;
import lombok.Getter;
import org.springframework.http.ProblemDetail;
import org.springframework.web.ErrorResponseException;

import java.time.OffsetDateTime;

/*
 Gateway에서 의도적으로 발생시키는 비즈니스 예외.

 Spring Framework의 ProblemDetail 기반 에러 응답을 사용하기 위해
 ErrorResponseException을 상속한다.

 별도의 ErrorResponse DTO를 만들지 않고,
 ProblemDetail 표준 필드와 확장 필드를 사용한다.
 */
@Getter
public class ApiException extends ErrorResponseException {

    private final ErrorCode errorCode;

    public ApiException(ErrorCode errorCode) {
        super(errorCode.getStatus(), createBody(errorCode), null);
        this.errorCode = errorCode;
    }

    /*
     ErrorCode를 ProblemDetail 응답 본문으로 변환한다.

     매핑 규칙:
     - status    : HTTP 상태 코드
     - title     : 비즈니스 에러 코드
     - detail    : 사용자에게 보여줄 메시지
     - timestamp : 에러 발생 시각
     */
    private static ProblemDetail createBody(ErrorCode errorCode) {
        ProblemDetail body = ProblemDetail.forStatus(errorCode.getStatus());
        body.setTitle(errorCode.getCode());
        body.setDetail(errorCode.getMessage());
        body.setProperty("timestamp", OffsetDateTime.now());
        return body;
    }
}