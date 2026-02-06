package kr.ac.ksj.secure_pj.secret.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.ac.ksj.secure_pj.secret.service.CustomUserDetailsService;
import kr.ac.ksj.secure_pj.secret.util.JwtUtil;
import kr.ac.ksj.secure_pj.secret.util.UserCacheRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final UserCacheRepository userCacheRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");
        //JWT 헤더가 있을 경우
        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            //JWT 유효성 검증
            if (jwtUtil.isValidToken(token)) {
                Long userId = jwtUtil.getUserId(token);

                // Cache에 해당 유저의 Authentication 객체 저장 확인
                UserDetails userDetails = userCacheRepository.get(String.valueOf(userId));

                // 없으면 DB 조회 후, UserDetails 객체 get
                // -> Cache에 객체 저장 -> Authentication 객체 저장
                if (userDetails == null) {
                    UserDetails newUserDetails = customUserDetailsService.loadUserByUsername(userId.toString());
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(newUserDetails, null, newUserDetails.getAuthorities());

                    userCacheRepository.save(newUserDetails);

                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
                // 있다면, Authentication 객체 생성 후 저장
                else {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }

            }
        }

        filterChain.doFilter(request, response); //다음 필터로 넘김
    }
}
