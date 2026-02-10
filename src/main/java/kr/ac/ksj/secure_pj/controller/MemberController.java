package kr.ac.ksj.secure_pj.controller;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.ac.ksj.secure_pj.domain.Member;
import kr.ac.ksj.secure_pj.domain.domain_enum.RoleType;
import kr.ac.ksj.secure_pj.exception.AuthException.NoRefreshTokenException;
import kr.ac.ksj.secure_pj.request_dto.CustomUserInfoDto;
import kr.ac.ksj.secure_pj.request_dto.LoginRequestDto;
import kr.ac.ksj.secure_pj.request_dto.MemberRequestDto;
import kr.ac.ksj.secure_pj.response_dto.LogInResponseDto;
import kr.ac.ksj.secure_pj.secret.util.JwtUtil;
import kr.ac.ksj.secure_pj.secret.util.UserCacheRepository;
import kr.ac.ksj.secure_pj.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/member")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;
    private final JwtUtil jwtUtil;

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody MemberRequestDto memberRequestDto) {
        memberService.save(memberRequestDto);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<?> logIn(@RequestBody LoginRequestDto loginRequestDto, HttpServletResponse response) {
        String tokens = memberService.logIn(loginRequestDto);
        String accessToken = tokens.split(" ")[0];
        String refreshToken = tokens.split(" ")[1];

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        ResponseCookie responseCookie = ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(true)
                .secure(true)        // HTTPS에서만 전송
                .path("/")           // 모든 경로에서 접근 가능
                .maxAge(7 * 24 * 60 * 60)  // 7일 (초 단위)
                .sameSite("Strict")  // CSRF 공격 방지
                .build();


        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .build();
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshTokens(@CookieValue(name = "refreshToken") String refreshToken,
                                           HttpServletResponse response) {

        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new NoRefreshTokenException("No refresh token provided");
        }

        if (!jwtUtil.isValidToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Refresh token is invalid");
        }

        String tokens = memberService.refresh(refreshToken);
        String accessToken = tokens.split(" ")[0];
        String newRefreshToken = tokens.split(" ")[1];

        // Refresh Token을 Secure Cookie로 설정
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", newRefreshToken)
                .httpOnly(true)      // JavaScript로 접근 불가
                .secure(true)        // HTTPS에서만 전송
                .path("/")           // 모든 경로에서 접근 가능
                .maxAge(7 * 24 * 60 * 60)  // 7일 (초 단위)
                .sameSite("Strict")  // CSRF 공격 방지
                .build();

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString()) // 쿠키 설정
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)    // 액세스 토큰 설정
                .body("Token issued successfully");
    }
}
