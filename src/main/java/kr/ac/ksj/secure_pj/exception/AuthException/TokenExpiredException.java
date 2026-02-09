package kr.ac.ksj.secure_pj.exception.AuthException;

public class TokenExpiredException extends RuntimeException {
    public TokenExpiredException(String message) {
        super(message);
    }
}
