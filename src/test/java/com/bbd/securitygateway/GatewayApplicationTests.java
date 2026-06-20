package com.bbd.securitygateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Instant;

@SpringBootTest
class GatewayApplicationTests {

	@Test
	void contextLoads() {
	}

	@TestConfiguration
	static class SecurityTestConfig {

		@Bean
		@Primary
		JwtDecoder jwtDecoder() {
			return token -> Jwt.withTokenValue(token)
					.header("alg", "none")
					.subject("test-user")
					.issuedAt(Instant.now())
					.expiresAt(Instant.now().plusSeconds(60))
					.build();
		}

		@Bean
		@Primary
		ClientRegistrationRepository clientRegistrationRepository() {
			ClientRegistration keycloak = ClientRegistration.withRegistrationId("keycloak")
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

			return new InMemoryClientRegistrationRepository(keycloak);
		}
	}
}
