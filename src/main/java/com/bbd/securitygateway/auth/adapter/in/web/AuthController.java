package com.bbd.securitygateway.auth.adapter.in.web;

import com.bbd.securitygateway.auth.adapter.in.web.response.CurrentUserResponse;
import com.bbd.securitygateway.auth.application.model.AuthPrincipal;
import com.bbd.securitygateway.auth.application.model.CurrentUserResult;
import com.bbd.securitygateway.auth.application.port.in.GetCurrentUserUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/*
 현재 브라우저 사용자의 Gateway 세션 로그인 상태와
 Keycloak/OIDC 기본 사용자 정보를 반환하는 Web Adapter.

 이 컨트롤러는 HTTP 요청/응답을 담당하는 adapter.in.web 계층에 속한다.

 역할:
 - Spring Security Authentication에서 현재 인증 사용자 정보를 읽는다.
 - Authentication/OidcUser 같은 프레임워크 타입을 AuthPrincipal로 변환한다.
 - application use case를 호출한다.
 - application 결과 모델인 CurrentUserResult를 CurrentUserResponse로 변환해 반환한다.

 role, tenancy, status, permission 같은 ERP 인가 판단은
 각 MSA의 경량 인가 프레임워크가 수행한다.
 */
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final GetCurrentUserUseCase getCurrentUserUseCase;

    /*
     현재 브라우저 사용자의 로그인 상태를 조회한다.

     프론트는 이 API를 호출해서
     1) 현재 Gateway 세션 기준 로그인되어 있는지
     2) 로그인되어 있다면 Keycloak/OIDC 기본 사용자 정보가 무엇인지
     확인할 수 있다.

     이 API는 ERP 사용자 등록 여부나 권한을 판단하지 않는다.
     */
    @GetMapping("/api/auth/me")
    public CurrentUserResponse me(Authentication authentication) {
        AuthPrincipal principal = toAuthPrincipal(authentication);

        CurrentUserResult result = getCurrentUserUseCase.getCurrentUser(principal);

        return CurrentUserResponse.from(result);
    }

    /*
     Spring Security의 Authentication을
     application 계층에서 사용할 AuthPrincipal로 변환한다.

     application 계층이 Spring Security의 Authentication, OidcUser 같은
     프레임워크 타입에 직접 의존하지 않도록 하기 위한 변환 메서드이다.

     로그인하지 않은 경우:
     - Authentication이 null
     - 인증되지 않은 Authentication
     - AnonymousAuthenticationToken

     위 경우에는 AuthPrincipal.unauthenticated()를 반환한다.
     */
    private AuthPrincipal toAuthPrincipal(Authentication authentication) {
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return AuthPrincipal.unauthenticated();
        }

        Object principal = authentication.getPrincipal();

        /*
         OIDC 로그인 성공 시 principal은 보통 OidcUser 타입이다.

         여기서는 Keycloak/OIDC claim에서 Gateway가 알아야 할
         최소 사용자 정보만 추출한다.

         role, tenancyType, tenancyName, status, permission은 추출하지 않는다.
         해당 값들은 Gateway 인증 정보가 아니라 각 MSA가 Redis UserSnapshot을 조회해서 판단할 인가 정보이다.
         */
        if (principal instanceof OidcUser oidcUser) {
            return AuthPrincipal.authenticated(
                    oidcUser.getSubject(),
                    oidcUser.getPreferredUsername(),
                    oidcUser.getClaimAsString("employee_number"),
                    oidcUser.getClaimAsString("name"),
                    oidcUser.getEmail(),
                    oidcUser.getClaimAsString("position")
            );
        }

        /*
         현재 인증 방식은 OIDC 로그인을 기준으로 한다.
         OidcUser가 아니라면 Gateway에서 해석할 수 있는 사용자 정보가 없으므로
         인증되지 않은 사용자로 처리한다.
         */
        return AuthPrincipal.unauthenticated();
    }
}