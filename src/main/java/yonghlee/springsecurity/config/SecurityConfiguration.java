package yonghlee.springsecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import yonghlee.springsecurity.entities.Role;
import yonghlee.springsecurity.service.UserService;

/**
 * 웹 보안 설정하고 JWT기반의 사용자 인증을 구현
 * @Configuration 어노테이션은 해당 클래스가 Spring의 설정 클래스임을 나타냅니다.
 * @EnableWebSecurity 어노테이션은 Spring Security를 사용하는 웹 보안을 활성화합니다
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserService userService;

    /**
     * securityFilterChain 메서드는 보안 필터 체인을 구성하는 데 사용됩니다.
     * .csrf(AbstractHttpConfigurer::disable)는 CSRF(Cross-Site Request Forgery) 보호를 비활성화합니다.
     * .authorizeHttpRequests는 HTTP 요청에 대한 권한을 설정합니다.
     * /api/v1/auth/**에 대한 요청은 인증 없이 허용하고, /api/v1/admin은 ADMIN 권한이 필요하며, /api/v1/user는 USER 권한이 필요합니다.
     * .sessionManagement은 세션 관리를 설정하며, SessionCreationPolicy.STATELESS는 세션을 사용하지 않음을 의미합니다.
     * .authenticationProvider(authenticationProvider())는 사용자 지정 인증 프로바이더를 설정합니다.
     * .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)는 JWT 인증 필터를 사용자 이름 및 비밀번호 인증 필터 전에 추가합니다.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> request.requestMatchers("/api/v1/auth/**")
                        .permitAll()
                        .requestMatchers("/api/v1/admin").hasAnyAuthority(Role.ADMIN.name())
                        .requestMatchers("/api/v1/user").hasAnyAuthority(Role.USER.name())
                        .anyRequest().authenticated())

                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider()).addFilterBefore(
                        jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class
                        );
                return http.build();
    }

    /**
     * authenticationProvider 메서드는 DaoAuthenticationProvider -> 데이터베이스에 저장된 사용자 정보를 이용하여 사용자를 인증하는 역할을 수행합니다. 이는 주로 사용자 이름과 비밀번호를 사용한 인증 방식에서 활용됩니다.를 생성하고 설정합니다.
     * userService.userDetailsService()를 통해 사용자 서비스를 등록하고, passwordEncoder()를 통해 비밀번호 인코더를 설정합니다.
     */
    @Bean
    public AuthenticationProvider authenticationProvider()
    {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userService.userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
        throws Exception {
        return config.getAuthenticationManager();
    }

}
