package yonghlee.springsecurity.config;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import yonghlee.springsecurity.service.JWTService;
import yonghlee.springsecurity.service.UserService;

import java.io.IOException;

/**
 * JWT 인증 처리 필터 클래스
 * SecurityContext는 현재 시큐리티에서 인증된 사용자의 보안 정보를 저장하는 객체
 * Holder는 컨텍스트를 관리하고 제공
 * Authentication : 현재 사용자의 인증 정보를 나타내는 객체
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // Authorization 헤더에서 JWT 추출 -> 단, 헤더가 비어있거나 Bearer로 시작하지 않으면 다음 필터로
        if (StringUtils.isEmpty(authHeader) || !org.apache.commons.lang3.StringUtils.startsWith(authHeader, "Bearer "))
        {
            filterChain.doFilter(request, response);
            return ;
        }

        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUserName(jwt);

        // 이메일이 존재하고 현재 SecurityContext에서 인증이 이루어지지 않았다면
        if (StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userService.userDetailsService().loadUserByUsername(userEmail);

            // 토큰이 유효하다면
            if (jwtService.isTokenValid(jwt, userDetails))
            {
                // SecurityContext를 새로 생성하여 인증 정보 설정
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );

                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);


            }
        }
        filterChain.doFilter(request, response);

    }
}
