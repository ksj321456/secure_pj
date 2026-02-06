package kr.ac.ksj.secure_pj.controller;

import kr.ac.ksj.secure_pj.domain.Member;
import kr.ac.ksj.secure_pj.request_dto.LoginRequestDto;
import kr.ac.ksj.secure_pj.request_dto.MemberRequestDto;
import kr.ac.ksj.secure_pj.response_dto.LogInResponseDto;
import kr.ac.ksj.secure_pj.secret.util.UserCacheRepository;
import kr.ac.ksj.secure_pj.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/member")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;
    private final UserCacheRepository UserCacheRepository;

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody MemberRequestDto memberRequestDto) {
        memberService.save(memberRequestDto);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<?> logIn(@RequestBody LoginRequestDto loginRequestDto) {
        String tokens = memberService.logIn(loginRequestDto);
        String accessToken = tokens.split(" ")[0];
        String refreshToken = tokens.split(" ")[1];

        LogInResponseDto logInResponseDto = LogInResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken).build();
        return ResponseEntity.ok(logInResponseDto);
    }
}
