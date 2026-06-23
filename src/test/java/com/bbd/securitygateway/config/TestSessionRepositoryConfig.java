package com.bbd.securitygateway.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@TestConfiguration
public class TestSessionRepositoryConfig {

    @Bean
    @Primary
    FindByIndexNameSessionRepository<MapSession> testSessionRepository() {
        return new InMemoryIndexedSessionRepository();
    }

    private static final class InMemoryIndexedSessionRepository
            implements FindByIndexNameSessionRepository<MapSession> {

        private static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(30);

        private final Map<String, MapSession> sessions = new ConcurrentHashMap<>();

        @Override
        public MapSession createSession() {
            MapSession session = new MapSession();
            session.setMaxInactiveInterval(DEFAULT_TIMEOUT);
            return session;
        }

        @Override
        public void save(MapSession session) {
            if (session.isExpired()) {
                deleteById(session.getId());
                return;
            }

            sessions.put(session.getId(), new MapSession(session));
        }

        @Override
        public MapSession findById(String id) {
            MapSession saved = sessions.get(id);
            if (saved == null) {
                return null;
            }

            if (saved.isExpired()) {
                deleteById(saved.getId());
                return null;
            }

            return new MapSession(saved);
        }

        @Override
        public void deleteById(String id) {
            sessions.remove(id);
        }

        @Override
        public Map<String, MapSession> findByIndexNameAndIndexValue(String indexName, String indexValue) {
            if (!PRINCIPAL_NAME_INDEX_NAME.equals(indexName)) {
                return Map.of();
            }

            Map<String, MapSession> matches = new ConcurrentHashMap<>();
            sessions.forEach((id, session) -> {
                String principalName = session.getAttribute(PRINCIPAL_NAME_INDEX_NAME);
                if (indexValue.equals(principalName) && !session.isExpired()) {
                    matches.put(id, new MapSession(session));
                }
            });
            return matches;
        }
    }
}
