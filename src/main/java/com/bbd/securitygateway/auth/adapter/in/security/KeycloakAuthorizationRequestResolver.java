package com.bbd.securitygateway.auth.adapter.in.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Set;

/*
 Keycloak 전용 authorization request 파라미터를 안전하게 전달한다.

 Spring Security의 기본 resolver는 프론트 요청의 임의 쿼리 파라미터를
 Keycloak authorization endpoint로 그대로 넘기지 않는다. 비밀번호 변경 required action은
 kc_action=UPDATE_PASSWORD가 필요하므로 허용된 값만 additionalParameters에 추가한다.
 */
@Component
public class KeycloakAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private static final String KC_ACTION_PARAMETER = "kc_action";
    private static final Set<String> ALLOWED_KC_ACTIONS = Set.of("UPDATE_PASSWORD");

    private final OAuth2AuthorizationRequestResolver delegate;

    public KeycloakAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                DefaultOAuth2AuthorizationRequestResolver.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
        );
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return customize(request, delegate.resolve(request));
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return customize(request, delegate.resolve(request, clientRegistrationId));
    }

    private OAuth2AuthorizationRequest customize(HttpServletRequest request,
                                                 OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null) {
            return null;
        }

        String kcAction = request.getParameter(KC_ACTION_PARAMETER);
        if (!StringUtils.hasText(kcAction) || !ALLOWED_KC_ACTIONS.contains(kcAction)) {
            return authorizationRequest;
        }

        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(parameters -> parameters.put(KC_ACTION_PARAMETER, kcAction))
                .build();
    }
}
