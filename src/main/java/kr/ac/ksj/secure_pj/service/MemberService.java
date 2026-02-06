package kr.ac.ksj.secure_pj.service;

import kr.ac.ksj.secure_pj.domain.Member;
import kr.ac.ksj.secure_pj.repository.MemberRepository;
import kr.ac.ksj.secure_pj.request_dto.CustomUserInfoDto;
import kr.ac.ksj.secure_pj.request_dto.LoginRequestDto;
import kr.ac.ksj.secure_pj.request_dto.MemberRequestDto;
import kr.ac.ksj.secure_pj.secret.util.JwtUtil;
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

    public void save(MemberRequestDto memberRequestDto) {
        Member member = Member.builder()
                .email(memberRequestDto.getEmail())
                .password(bCryptPasswordEncoder.encode(memberRequestDto.getPassword()))
                .name(memberRequestDto.getName())
                .role(memberRequestDto.getRole())
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
        return response;
    }
}
