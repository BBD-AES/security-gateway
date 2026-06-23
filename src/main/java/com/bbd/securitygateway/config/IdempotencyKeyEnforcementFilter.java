package com.bbd.securitygateway.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/*
 멱등 표준(docs/idempotency-spec.md): 변경 라우트에 Idempotency-Key 헤더를 "강제".

 게이트웨이의 역할 = 헤더 강제 + 전파뿐. 멱등 판정(dedup)은 하지 않는다 — 그건 각 MSA(공유 라이브러리/DB UNIQUE)의 몫.
 (헤더 자체는 Spring Cloud Gateway 가 기본 전파하므로 별도 전파 코드는 불필요.)

 안전 설계:
 - POST 에만 강제한다. PATCH 는 "부수효과 있는 상태전이"와 "자연 멱등"이 섞여 게이트웨이가 구분할 수 없으므로
   PATCH 강제는 각 서비스가 담당(spec §1). 게이트웨이가 모든 PATCH 를 막으면 정당한 멱등 PATCH 가 400 으로 깨질 수 있다.
 - 백엔드 서비스 prefix 로 가는 POST 에만 적용 — oauth2/login/정적 리소스 POST 는 제외.
 - bbd.idempotency.enforce-enabled=false 로 끌 수 있다.
*/
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
@ConditionalOnProperty(prefix = "bbd.idempotency", name = "enforce-enabled", havingValue = "true", matchIfMissing = true)
public class IdempotencyKeyEnforcementFilter extends OncePerRequestFilter {

    private static final String HEADER = "Idempotency-Key";
    private static final String MISSING_HEADER_BODY =
            "{\"code\":\"IDEM400\",\"message\":\"Idempotency-Key 헤더가 필요합니다.\"}";
    // 변경 API 가 사는 백엔드 서비스 prefix. POST 가 이 경로로 갈 때만 헤더를 강제.
    private static final List<String> MUTATING_PREFIXES =
            List.of("/item", "/inventory", "/sales", "/procurement", "/user");
    // 비-멱등(조회성) POST 는 강제 제외 — 예: /api/v1/items/search/bulk(검색). 부수효과 없는 쿼리는 멱등키 불필요.
    private static final List<String> QUERY_POST_PATTERNS = List.of("/search");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (requiresKey(request) && !StringUtils.hasText(request.getHeader(HEADER))) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(MISSING_HEADER_BODY);
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean requiresKey(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        String path = request.getRequestURI();
        boolean mutating = MUTATING_PREFIXES.stream().anyMatch(p -> path.equals(p) || path.startsWith(p + "/"));
        if (!mutating) {
            return false;
        }
        // 조회성 POST(검색 등)는 멱등키 강제 대상에서 제외.
        return QUERY_POST_PATTERNS.stream().noneMatch(path::contains);
    }
}
