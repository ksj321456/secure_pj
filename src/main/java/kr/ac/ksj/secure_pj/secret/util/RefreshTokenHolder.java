package kr.ac.ksj.secure_pj.secret.util;

import java.time.LocalDateTime;

public record RefreshTokenHolder(String refreshToken, LocalDateTime expiresAt) {

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}
