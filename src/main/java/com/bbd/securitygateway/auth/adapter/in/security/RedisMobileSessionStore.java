package com.bbd.securitygateway.auth.adapter.in.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * 모바일 단일 기기 세션 저장소(Redis). 값 = "sid|authEpochSeconds".
 *
 * register/validate 와 remove 를 모두 <b>Lua 스크립트로 원자화</b>한다.
 * 비원자 GET→비교→SET 은 동시 로그인 시 둘 다 current==null 을 보고 양쪽 다 통과할 수 있어(레이스),
 * 단일 기기 보장이 깨졌다. 원자 스크립트로 GET·비교·SET 을 한 호출에 묶어 이를 제거한다.
 *
 * 점유 규칙(다른 sid): 이미 등록된 모바일 세션이 있으면 신규 sid 를 차단한다.
 * 같은 sid 는 항상 통과(토큰 refresh = TTL 갱신)하고, 로그아웃으로 슬롯이 비워진 뒤에만 다른 기기가 등록된다.
 * 즉 "신규 로그인으로 기존 기기 끊기"가 아니라 "기존 기기가 살아 있으면 신규 기기 차단" 정책이다.
 */
@Component
@ConditionalOnBean(StringRedisTemplate.class)
@RequiredArgsConstructor
public class RedisMobileSessionStore implements MobileSessionStore {

    // KEYS[1]=세션키, ARGV[1]=sid, ARGV[2]=authEpochSeconds, ARGV[3]=ttlSeconds.
    // 반환 1=점유(SET 함, 통과) / 0=차단(이미 다른 기기가 점유 중).
    private static final RedisScript<Long> REGISTER_OR_VALIDATE = new DefaultRedisScript<>("""
            local cur = redis.call('GET', KEYS[1])
            local sid = ARGV[1]
            local ttl = tonumber(ARGV[3])
            local take = false
            if cur == false then
                take = true
            else
                local i = string.find(cur, '|', 1, true)
                if i == nil then
                    take = true
                else
                    local curSid = string.sub(cur, 1, i - 1)
                    if curSid == sid then
                        take = true
                    end
                end
            end
            if take then
                redis.call('SET', KEYS[1], sid .. '|' .. ARGV[2], 'EX', ttl)
                return 1
            end
            return 0
            """, Long.class);

    // 저장된 current 가 내 sid 일 때만 삭제(로그아웃) — 다른 기기가 이미 점유했으면 건드리지 않음. 원자.
    private static final RedisScript<Long> REMOVE_IF_CURRENT = new DefaultRedisScript<>("""
            local cur = redis.call('GET', KEYS[1])
            if cur == false then return 0 end
            local i = string.find(cur, '|', 1, true)
            local curSid = cur
            if i ~= nil then curSid = string.sub(cur, 1, i - 1) end
            if curSid == ARGV[1] then
                redis.call('DEL', KEYS[1])
                return 1
            end
            return 0
            """, Long.class);

    private final StringRedisTemplate redisTemplate;
    private final MobileSessionProperties properties;

    @Override
    public boolean registerOrValidate(String userSub, String sessionId, Instant authenticatedAt, Duration ttl) {
        Long result = redisTemplate.execute(
                REGISTER_OR_VALIDATE,
                List.of(key(userSub)),
                sessionId,
                String.valueOf(authenticatedAt.getEpochSecond()),
                String.valueOf(Math.max(1L, ttl.getSeconds()))
        );
        return result != null && result == 1L;
    }

    @Override
    public void removeIfCurrent(String userSub, String sessionId) {
        redisTemplate.execute(REMOVE_IF_CURRENT, List.of(key(userSub)), sessionId);
    }

    private String key(String userSub) {
        return properties.getKeyPrefix() + ":" + userSub;
    }
}
