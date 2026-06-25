package com.bbd.securitygateway.auth.adapter.in.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Component
@ConditionalOnBean(StringRedisTemplate.class)
@RequiredArgsConstructor
public class RedisMobileSessionStore implements MobileSessionStore {

    private static final String DELIMITER = "|";

    private final StringRedisTemplate redisTemplate;
    private final MobileSessionProperties properties;

    @Override
    public boolean registerOrValidate(String userSub, String sessionId, Instant authenticatedAt, Duration ttl) {
        String key = key(userSub);
        MobileSessionRecord incoming = new MobileSessionRecord(sessionId, authenticatedAt);
        MobileSessionRecord current = MobileSessionRecord.parse(redisTemplate.opsForValue().get(key));

        if (current == null || current.isSameSession(sessionId) || incoming.isSameOrNewerThan(current)) {
            redisTemplate.opsForValue().set(key, incoming.serialize(), ttl);
            return true;
        }

        return false;
    }

    @Override
    public void removeIfCurrent(String userSub, String sessionId) {
        String key = key(userSub);
        MobileSessionRecord current = MobileSessionRecord.parse(redisTemplate.opsForValue().get(key));
        if (current != null && current.isSameSession(sessionId)) {
            redisTemplate.delete(key);
        }
    }

    private String key(String userSub) {
        return properties.getKeyPrefix() + ":" + userSub;
    }

    private record MobileSessionRecord(String sessionId, Instant authenticatedAt) {

        private String serialize() {
            return sessionId + DELIMITER + authenticatedAt.getEpochSecond();
        }

        private boolean isSameSession(String sessionId) {
            return this.sessionId.equals(sessionId);
        }

        private boolean isSameOrNewerThan(MobileSessionRecord other) {
            return !authenticatedAt.isBefore(other.authenticatedAt);
        }

        private static MobileSessionRecord parse(String value) {
            if (value == null || value.isBlank()) {
                return null;
            }

            String[] parts = value.split("\\|", 2);
            if (parts.length != 2 || parts[0].isBlank()) {
                return null;
            }

            try {
                return new MobileSessionRecord(parts[0], Instant.ofEpochSecond(Long.parseLong(parts[1])));
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
    }
}
