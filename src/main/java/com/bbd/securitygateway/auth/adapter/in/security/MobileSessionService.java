package com.bbd.securitygateway.auth.adapter.in.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class MobileSessionService {

    private static final String AUTHORIZED_PARTY_CLAIM = "azp";
    private static final String CLIENT_ID_CLAIM = "client_id";
    private static final String SESSION_ID_CLAIM = "sid";
    private static final String AUTH_TIME_CLAIM = "auth_time";

    private final MobileSessionProperties properties;
    private final ObjectProvider<MobileSessionStore> mobileSessionStoreProvider;

    public boolean validate(Jwt jwt) {
        if (!properties.isEnabled() || !isMobileClient(jwt)) {
            return true;
        }

        String userSub = jwt.getSubject();
        String sessionId = jwt.getClaimAsString(SESSION_ID_CLAIM);
        if (!hasText(userSub) || !hasText(sessionId)) {
            return false;
        }

        MobileSessionStore mobileSessionStore = mobileSessionStoreProvider.getIfAvailable();
        if (mobileSessionStore == null) {
            return true;
        }

        return mobileSessionStore.registerOrValidate(
                userSub,
                sessionId,
                authenticatedAt(jwt),
                properties.getTtl()
        );
    }

    public void logout(Jwt jwt) {
        if (!properties.isEnabled() || !isMobileClient(jwt)) {
            return;
        }

        String userSub = jwt.getSubject();
        String sessionId = jwt.getClaimAsString(SESSION_ID_CLAIM);
        MobileSessionStore mobileSessionStore = mobileSessionStoreProvider.getIfAvailable();
        if (mobileSessionStore != null && hasText(userSub) && hasText(sessionId)) {
            mobileSessionStore.removeIfCurrent(userSub, sessionId);
        }
    }

    private boolean isMobileClient(Jwt jwt) {
        String clientId = properties.getClientId();
        if (!hasText(clientId)) {
            return false;
        }

        return clientId.equals(jwt.getClaimAsString(AUTHORIZED_PARTY_CLAIM))
                || clientId.equals(jwt.getClaimAsString(CLIENT_ID_CLAIM));
    }

    private Instant authenticatedAt(Jwt jwt) {
        Instant authTime = jwt.getClaimAsInstant(AUTH_TIME_CLAIM);
        if (authTime != null) {
            return authTime;
        }

        Instant issuedAt = jwt.getIssuedAt();
        return issuedAt == null ? Instant.EPOCH : issuedAt;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
