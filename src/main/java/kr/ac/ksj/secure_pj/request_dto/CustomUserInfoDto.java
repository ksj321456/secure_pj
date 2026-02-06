package kr.ac.ksj.secure_pj.request_dto;

import kr.ac.ksj.secure_pj.domain.domain_enum.RoleType;
import kr.ac.ksj.secure_pj.dto.MemberDto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class CustomUserInfoDto extends MemberDto {

    private Long memberId;
    private String email;
    private String password;
    private String name;
    private RoleType role;
}