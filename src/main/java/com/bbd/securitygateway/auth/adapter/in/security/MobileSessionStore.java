package com.bbd.securitygateway.auth.adapter.in.security;

import java.time.Duration;
import java.time.Instant;

public interface MobileSessionStore {

    boolean registerOrValidate(String userSub, String sessionId, Instant authenticatedAt, Duration ttl);

    void removeIfCurrent(String userSub, String sessionId);
}
