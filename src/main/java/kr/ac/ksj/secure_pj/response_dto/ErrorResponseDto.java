package kr.ac.ksj.secure_pj.response_dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class ErrorResponseDto {

    private int status;

    private String message;

    private LocalDateTime timestamp;
}
