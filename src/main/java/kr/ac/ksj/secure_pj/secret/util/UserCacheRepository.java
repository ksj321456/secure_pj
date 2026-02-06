package kr.ac.ksj.secure_pj.secret.util;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class UserCacheRepository {

    // Key: UserId, Value: UserDetails
    private final Map<String, UserDetails> userCache = new ConcurrentHashMap<>();

    // 여기서의 username은 정수형 ID임.
    public void save(UserDetails user) {
        userCache.put(user.getUsername(), user);
    }

    public UserDetails get(String userId) {
        return userCache.get(userId);
    }

    public void remove(String userId) {
        userCache.remove(userId);
    }
}
