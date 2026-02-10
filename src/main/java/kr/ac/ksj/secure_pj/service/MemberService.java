package kr.ac.ksj.secure_pj.service;

import io.jsonwebtoken.Claims;
import kr.ac.ksj.secure_pj.domain.Member;
import kr.ac.ksj.secure_pj.domain.domain_enum.RoleType;
import kr.ac.ksj.secure_pj.repository.MemberRepository;
import kr.ac.ksj.secure_pj.request_dto.CustomUserInfoDto;
import kr.ac.ksj.secure_pj.request_dto.LoginRequestDto;
import kr.ac.ksj.secure_pj.request_dto.MemberRequestDto;
import kr.ac.ksj.secure_pj.secret.util.JwtUtil;
import kr.ac.ksj.secure_pj.secret.util.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder bCryptPasswordEncoder;
    private final ModelMapper modelMapper;
    private final RefreshTokenRepository refreshTokenRepository;

    public void save(MemberRequestDto memberRequestDto) {

        RoleType roleType = null;
        if (memberRequestDto.getName().equals("admin")) {
            roleType = RoleType.ADMIN;
        } else {
            roleType = RoleType.USER;
        }

        Member member = Member.builder()
                .email(memberRequestDto.getEmail())
                .password(bCryptPasswordEncoder.encode(memberRequestDto.getPassword()))
                .name(memberRequestDto.getName())
                .role(roleType)
                .build();

        memberRepository.save(member);
    }

    public String logIn(LoginRequestDto loginRequestDto) {
        String email = loginRequestDto.getEmail();
        String password = loginRequestDto.getPassword();

        Optional<Member> memberOptional = memberRepository.findByEmail(email);
        Member member = memberOptional.get();

        CustomUserInfoDto info = modelMapper.map(member, CustomUserInfoDto.class);
        String accessToken = jwtUtil.createAccessToken(info);
        String refreshToken = jwtUtil.createRefreshToken(info);

        String response = accessToken + " " + refreshToken;

        // tokenStroage에 저장, 10080분 => 7일동안 유효
        String userId = member.getId().toString();
        refreshTokenRepository.saveRefreshToken(userId, refreshToken, 10080);

        return response;
    }

    public String refresh(String refreshToken) {
        Claims claims = jwtUtil.parseClaims(refreshToken);
        Long memberId = jwtUtil.getUserId(refreshToken);
        String email = claims.get("email", String.class);
        String name = claims.get("name", String.class);
        RoleType roleType = RoleType.valueOf(claims.get("role", String.class));
        CustomUserInfoDto customUserInfoDto = CustomUserInfoDto.builder()
                .role(roleType)
                .memberId(memberId)
                .email(email)
                .name(name).build();

        String accessToken = jwtUtil.createAccessToken(customUserInfoDto);
        String newRefreshToken = jwtUtil.createRefreshToken(customUserInfoDto);

        refreshTokenRepository.saveRefreshToken(memberId.toString(), newRefreshToken, 10080);

        return accessToken + " " + newRefreshToken;
    }
}
