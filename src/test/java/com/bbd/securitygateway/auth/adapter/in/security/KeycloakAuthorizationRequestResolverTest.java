package com.bbd.securitygateway.auth.adapter.in.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeycloakAuthorizationRequestResolverTest {

    private final KeycloakAuthorizationRequestResolver resolver =
            new KeycloakAuthorizationRequestResolver(new InMemoryClientRegistrationRepository(keycloak()));

    @Test
    void update_password_kc_action을_keycloak_authorization_request에_전달한다() {
        MockHttpServletRequest request = authorizationRequest();
        request.setParameter("kc_action", "UPDATE_PASSWORD");

        OAuth2AuthorizationRequest authorizationRequest = resolver.resolve(request);

        assertNotNull(authorizationRequest);
        assertEquals("UPDATE_PASSWORD", authorizationRequest.getAdditionalParameters().get("kc_action"));
        assertTrue(authorizationRequest.getAuthorizationRequestUri().contains("kc_action=UPDATE_PASSWORD"));
    }

    @Test
    void 허용되지_않은_kc_action은_전달하지_않는다() {
        MockHttpServletRequest request = authorizationRequest();
        request.setParameter("kc_action", "DELETE_ACCOUNT");

        OAuth2AuthorizationRequest authorizationRequest = resolver.resolve(request);

        assertNotNull(authorizationRequest);
        assertFalse(authorizationRequest.getAdditionalParameters().containsKey("kc_action"));
        assertFalse(authorizationRequest.getAuthorizationRequestUri().contains("kc_action="));
    }

    private MockHttpServletRequest authorizationRequest() {
        return new MockHttpServletRequest("GET", "/oauth2/authorization/keycloak");
    }

    private ClientRegistration keycloak() {
        return ClientRegistration.withRegistrationId("keycloak")
                .clientId("test-client")
                .clientSecret("test-secret")
                .clientName("keycloak")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email")
                .authorizationUri("http://localhost/oauth2/authorize")
                .tokenUri("http://localhost/oauth2/token")
                .jwkSetUri("http://localhost/oauth2/jwks")
                .userInfoUri("http://localhost/userinfo")
                .userNameAttributeName("sub")
                .build();
    }
}
