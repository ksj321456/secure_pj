package kr.ac.ksj.secure_pj.exception.AuthException;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class AuthenticationExceptionHandler {

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<?> tokenExpiredException(TokenExpiredException e) {
        log.info("Token expired, redirecting to token refresh endpoint");

        // 방법 1: 리다이렉트 URL을 응답으로 반환
        Map<String, String> response = new HashMap<>();
        response.put("message", e.getMessage());
        response.put("redirectUrl", "/member/refresh");

        // 401 상태 코드 와 발급 요청 URL 함께 전송
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(response);
    }

    @ExceptionHandler(NoRefreshTokenException.class)
    public ResponseEntity<?> noRefreshTokenException(NoRefreshTokenException e) {
        log.info("No refresh token, redirecting to token refresh endpoint");
        Map<String, String> response = new HashMap<>();
        response.put("message", e.getMessage());
        response.put("redirectUrl", "/member/refresh");

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(response);
    }
}
