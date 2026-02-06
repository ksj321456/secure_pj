package kr.ac.ksj.secure_pj.secret.service;

import kr.ac.ksj.secure_pj.domain.Member;
import kr.ac.ksj.secure_pj.repository.MemberRepository;
import kr.ac.ksj.secure_pj.request_dto.CustomUserInfoDto;
import kr.ac.ksj.secure_pj.secret.details.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // JWT에서 꺼낸 userId (String) → Long 변환
        Long memberId;
        try {
            memberId = Long.parseLong(username);
        } catch (NumberFormatException e) {
            throw new UsernameNotFoundException("Invalid memberId: " + username);
        }

        // DB에서 사용자 조회
        Member memberObject = memberRepository.findById(memberId)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with id: " + memberId)
                );

        CustomUserInfoDto member = new CustomUserInfoDto(memberObject.getId(), memberObject.getEmail(), memberObject.getEmail(), memberObject.getPassword(), memberObject.getRole());

        // CustomUserDetails로 감싸서 반환
        return new CustomUserDetails(member);
    }
}
