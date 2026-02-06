package kr.ac.ksj.secure_pj.secret.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.ac.ksj.secure_pj.response_dto.ErrorResponseDto;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.time.LocalDateTime;

@Component
@AllArgsConstructor
@Slf4j(topic = "UNAUTHORIZED_EXCEPTION_HANDLER")
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, org.springframework.security.core.AuthenticationException authException) throws IOException, ServletException {
        log.error("Not Authenticated", authException);

        // 401 Unauthorized 에러 응답 생성
        ErrorResponseDto errorResponseDto = new ErrorResponseDto(
                HttpStatus.UNAUTHORIZED.value(),
                "인증이 필요한 서비스입니다. 토큰을 확인해주세요.",
                LocalDateTime.now()
        );

        String responseBody = objectMapper.writeValueAsString(errorResponseDto);

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(responseBody);
    }
}
