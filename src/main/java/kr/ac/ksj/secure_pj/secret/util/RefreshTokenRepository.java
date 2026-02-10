package kr.ac.ksj.secure_pj.secret.util;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RefreshTokenRepository {

    private final Map<String, RefreshTokenHolder> tokenStorage = new ConcurrentHashMap<>();

    public void saveRefreshToken(String userId, String refreshToken, long durationMinutes) {
        tokenStorage.put(userId, new RefreshTokenHolder(refreshToken, LocalDateTime.now().plusMinutes(durationMinutes)));
    }

    public String get(String userId) {
        RefreshTokenHolder holder = tokenStorage.get(userId);
        if (holder != null && !holder.isExpired()) {
            return holder.refreshToken();
        }
        tokenStorage.remove(userId); // 조회 시 만료됐으면 삭제
        return null;
    }

    public void remove(String userId) {
        tokenStorage.remove(userId);
    }

    /**
     * 주기적으로 만료된 토큰 청소 (매 1시간마다 실행)
     * 연습용 프로젝트에서는 서버 메모리 관리를 위해 필수!
     */
    @Scheduled(fixedRate = 3600000) // 1시간 = 3,600,000ms
    public void cleanupExpiredTokens() {
        int initialSize = tokenStorage.size();

        // 만료된 항목들을 찾아서 삭제
        tokenStorage.entrySet().removeIf(entry -> entry.getValue().isExpired());

        int removedCount = initialSize - tokenStorage.size();
        if (removedCount > 0) {
            System.out.println("[Scheduled] 만료된 Refresh Token " + removedCount + "개를 삭제했습니다.");
        }
    }
}
