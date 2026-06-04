package com.bbd.securitygateway.auth;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class AuthController {

    /*
    현재 브라우저 사용자의 로그인 상태와 기본 사용자 정보를 반환하는 API.
     프론트는 이 API를 호출해서
     1) 현재 로그인된 사용자인지
     2) 로그인되어 있다면 어떤 사용자 정보가 있는지를 확인할 수 있다.
     */

    @GetMapping("/api/auth/me")
    public Map<String, Object> me(Authentication authentication) {

        // 응답 데이터를 담을 Map
        Map<String, Object> result = new HashMap<>();

        /*
         Authentication 객체는 Spring Security가 현재 요청의 인증 정보를 담아 넘겨준다.

         로그인하지 않은 경우에도 Spring Security 설정에 따라
         AnonymousAuthenticationToken이 들어올 수 있다.

         따라서 단순히 authentication != null 만으로는
         실제 로그인 사용자인지 판단하면 안 된다.
         */

        System.out.println("========== /api/auth/me ==========");
        System.out.println("authentication = " + authentication);

        if (authentication != null) {
            System.out.println("authentication class = " + authentication.getClass().getName());
            System.out.println("authentication name = " + authentication.getName());
            System.out.println("isAuthenticated = " + authentication.isAuthenticated());
            System.out.println("authorities = " + authentication.getAuthorities());
            System.out.println("principal class = " + authentication.getPrincipal().getClass().getName());
            System.out.println("principal = " + authentication.getPrincipal());
        }


        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {

            // 실제 로그인 사용자가 아니므로 authenticated=false 반환
            result.put("authenticated", false);
            return result;
        }

        /*
         여기까지 왔다면 authentication이 null이 아니고,
         인증 완료 상태이며,
         AnonymousAuthenticationToken도 아니므로
         Spring Security 기준 실제 로그인 사용자라고 판단할 수 있다.
         */

        result.put("authenticated", true);
        result.put("principalName", authentication.getName());

        Object principal = authentication.getPrincipal();

        if (principal instanceof OidcUser oidcUser) {
            result.put("username", oidcUser.getPreferredUsername());
            result.put("employeeNumber", oidcUser.getClaimAsString("employee_number"));
            result.put("sub", oidcUser.getSubject());

            result.put("displayName", oidcUser.getClaimAsString("name"));
            result.put("role", oidcUser.getClaimAsString("role"));
            result.put("tenancyType", oidcUser.getClaimAsString("tenancy_type"));
            result.put("tenancyName", oidcUser.getClaimAsString("tenancy_name"));
            result.put("position", oidcUser.getClaimAsString("position"));
        }

        // 최종적으로 로그인 여부와 사용자 정보를 JSON 형태로 반환한다.
        return result;
    }
}