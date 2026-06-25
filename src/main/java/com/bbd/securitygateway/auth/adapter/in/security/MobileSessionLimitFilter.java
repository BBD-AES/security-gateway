package com.bbd.securitygateway.auth.adapter.in.security;

import com.bbd.securitygateway.global.error.ApiException;
import com.bbd.securitygateway.global.error.dto.ErrorCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class MobileSessionLimitFilter extends OncePerRequestFilter {

    private final MobileSessionService mobileSessionService;
    private final HandlerExceptionResolver exceptionResolver;

    public MobileSessionLimitFilter(
            MobileSessionService mobileSessionService,
            @Qualifier("handlerExceptionResolver") HandlerExceptionResolver exceptionResolver
    ) {
        this.mobileSessionService = mobileSessionService;
        this.exceptionResolver = exceptionResolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication
                && !mobileSessionService.validate(jwtAuthentication.getToken())) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
            exceptionResolver.resolveException(
                    request,
                    response,
                    null,
                    new ApiException(ErrorCode.AUTH_MOBILE_SESSION_REPLACED)
            );
            return;
        }

        filterChain.doFilter(request, response);
    }
}
