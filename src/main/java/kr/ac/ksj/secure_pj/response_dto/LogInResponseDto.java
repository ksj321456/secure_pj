package kr.ac.ksj.secure_pj.response_dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LogInResponseDto {

    private String accessToken;
    private String refreshToken;
}
