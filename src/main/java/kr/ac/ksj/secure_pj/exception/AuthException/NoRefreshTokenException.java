package kr.ac.ksj.secure_pj.exception.AuthException;

public class NoRefreshTokenException extends RuntimeException {
    public NoRefreshTokenException(String message) {
        super(message);
    }
}
