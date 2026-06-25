package com.bbd.securitygateway.auth.adapter.in.web;

import com.bbd.securitygateway.auth.adapter.in.security.MobileSessionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MobileAuthController {

    private final MobileSessionService mobileSessionService;

    @PostMapping("/api/auth/mobile/logout")
    public ResponseEntity<Void> logout(JwtAuthenticationToken authentication) {
        if (authentication != null) {
            mobileSessionService.logout(authentication.getToken());
        }
        return ResponseEntity.noContent().build();
    }
}
